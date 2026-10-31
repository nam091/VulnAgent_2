"""Unit tests for intra-procedural backward AST slicing (src/context/ast_slicer.py).

Implements the standard test fixtures specified in Section 3.1 and Section 3.5.2
of Phuong_an_2.md:
1. `test_direct_taint`: Direct taint slice extraction from sink back to input/source.
2. `test_loop_fixpoint`: Fixpoint analysis convergence over loops (while/for) updating tainted vars.
3. `test_branch_merge`: Conditional branching (if/else) assigning distinct tainted variables, merged before sink.
4. `test_sanitization_check`: Capturing CWE-specific sanitizer/defense statements between source and sink.
5. `test_attribute_and_call_chain`: Tracing data flow across object attributes (obj.attr) and method call chains.
6. `test_budget_partial_fallback`: Safe fallback to completeness_status="partial" when loop or line budgets are exceeded.
"""

from __future__ import annotations

import pytest

from context.ast_slicer import (
    ASTSlicer,
    SliceNode,
    SliceResult,
    SinkAnchor,
    ABSTRACT_SINK_CATEGORIES,
    HEURISTIC_SINK_SUFFIXES,
    HEURISTIC_SINK_OBJECT_PREFIXES,
    SINK_CALL_SIGNATURES,
    COMPLETENESS_COMPLETE,
    COMPLETENESS_PARTIAL,
    COMPLETENESS_FAILED,
    get_sink_category,
    find_sink_anchors,
    find_call_site_sink_anchors,
)


@pytest.fixture
def slicer() -> ASTSlicer:
    """Default ASTSlicer instance."""
    return ASTSlicer()


# ---------------------------------------------------------------------------
# 1. test_direct_taint
# ---------------------------------------------------------------------------

def test_direct_taint(slicer: ASTSlicer) -> None:
    """Fixture 1: Trích xuất lát cắt từ sink thẳng tới input/source qua gán biến trực tiếp.

    Mục tiêu (Section 3.1 & 3.5.2):
    - Lần ngược biến qua chuỗi gán tuần tự nhiều bước (sink -> final_sql -> temp_var -> user_id).
    - Loại bỏ triệt để các biến chết (dead variables/dead code) không ảnh hưởng tới sink.
    - Bảo đảm completeness_status == 'complete' và is_truncated is False.
    """
    code = (
        "def process_query(user_id):\n"
        "    unused_dead_code = 'ignore_me'\n"
        "    temp_var = user_id\n"
        "    final_sql = f'SELECT * FROM accounts WHERE id = {temp_var}'\n"
        "    cursor.execute(final_sql)\n"
    )
    sink_line = 5

    res = slicer.slice_from_sink(code, sink_line, target_var="final_sql")

    # Assert basic completeness contract
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.is_complete is True
    assert res.is_truncated is False
    assert res.sink_name == "cursor.execute"
    assert res.target_variable == "final_sql"

    # Dead code elimination: line 2 ('unused_dead_code') must be strictly excluded
    assert 2 not in res.sliced_lines
    assert "unused_dead_code" not in res.sliced_code

    # Sliced lines must preserve function signature, def chain, and sink call
    assert res.sliced_lines == [1, 3, 4, 5]
    assert "temp_var = user_id" in res.sliced_code
    assert "cursor.execute(final_sql)" in res.sliced_code

    # Verify nodes & dependency chain
    nodes_by_line = {node.line_number: node for node in res.nodes}
    assert 1 in nodes_by_line
    assert nodes_by_line[1].node_type == "FunctionDef"
    assert "user_id" in nodes_by_line[1].variables_defined

    assert 3 in nodes_by_line
    assert nodes_by_line[3].node_type == "Assign"
    assert "temp_var" in nodes_by_line[3].variables_defined
    assert "user_id" in nodes_by_line[3].variables_used

    assert 4 in nodes_by_line
    assert nodes_by_line[4].node_type == "Assign"
    assert "final_sql" in nodes_by_line[4].variables_defined
    assert "temp_var" in nodes_by_line[4].variables_used

    assert 5 in nodes_by_line
    assert nodes_by_line[5].node_type == "Call"
    assert "final_sql" in nodes_by_line[5].variables_used

    # Data dependencies check: 5 -> 4 -> 3 -> 1
    assert 4 in res.data_dependencies[5]
    assert 3 in res.data_dependencies[4]
    assert 1 in res.data_dependencies[3]

    # Prompt rendering helper
    facts = res.to_facts_prompt()
    assert "cursor.execute" in facts
    assert "temp_var" in facts
    assert res.get_verified_facts_str() == facts


# ---------------------------------------------------------------------------
# 2. test_loop_fixpoint
# ---------------------------------------------------------------------------

def test_loop_fixpoint(slicer: ASTSlicer) -> None:
    """Fixture 2: Phân tích fixpoint đạt hội tụ qua vòng lặp (while/for) cập nhật biến tainted.

    Mục tiêu (Section 3.1.3 & 3.5.2):
    - Biến tích lũy luân chuyển trong vòng lặp (for, while) đạt điểm bất động (IN_{t+1} == IN_t).
    - Thuật toán kết thúc thành công với completeness_status == 'complete', không rơi vào vô hạn.
    - Sliced lines thu thập định nghĩa khởi tạo, câu lệnh lặp, câu lệnh tích lũy và sink.
    """
    # 2a. For loop fixpoint
    code_for = (
        "def build_query(items):\n"
        "    sql = 'SELECT * FROM products WHERE 1=1'\n"
        "    for item in items:\n"
        "        sql += f' AND name = {item}'\n"
        "    cursor.execute(sql)\n"
    )
    res_for = slicer.slice_from_sink(code_for, 5, target_var="sql")

    assert res_for.completeness_status == COMPLETENESS_COMPLETE
    assert res_for.is_complete is True
    assert res_for.is_truncated is False
    assert res_for.reason == "backward_slice_complete"
    assert res_for.sliced_lines == [1, 2, 3, 4, 5]

    # Verify loop node types and dependency reasons
    for_nodes = {node.line_number: node for node in res_for.nodes}
    assert for_nodes[2].node_type == "Assign"
    assert for_nodes[3].node_type == "For"
    assert "loop_iter" in for_nodes[3].dependency_reason
    assert for_nodes[4].node_type == "AugAssign"
    assert "loop_accum" in for_nodes[4].dependency_reason
    assert for_nodes[5].node_type == "Call"

    # Data dependencies: sink (5) depends on initial assign (2) and accum (4)
    assert 2 in res_for.data_dependencies[5] or 4 in res_for.data_dependencies[5]
    assert 2 in res_for.data_dependencies[4]
    assert 3 in res_for.data_dependencies[4]

    # 2b. While loop fixpoint
    code_while = (
        "def build_query_while(items):\n"
        "    sql = 'SELECT * FROM products WHERE 1=1'\n"
        "    i = 0\n"
        "    while i < len(items):\n"
        "        sql += f' AND name = {items[i]}'\n"
        "        i += 1\n"
        "    cursor.execute(sql)\n"
    )
    res_while = slicer.slice_from_sink(code_while, 7, target_var="sql")

    assert res_while.completeness_status == COMPLETENESS_COMPLETE
    assert res_while.is_complete is True
    assert res_while.is_truncated is False
    assert 2 in res_while.sliced_lines  # sql initial
    assert 4 in res_while.sliced_lines  # while condition
    assert 5 in res_while.sliced_lines  # sql accumulator
    assert 7 in res_while.sliced_lines  # cursor.execute(sql)


# ---------------------------------------------------------------------------
# 3. test_branch_merge
# ---------------------------------------------------------------------------

def test_branch_merge(slicer: ASTSlicer) -> None:
    """Fixture 3: Nhánh rẽ if/else gán biến tainted khác nhau và merge lại trước sink.

    Mục tiêu (Section 3.1.3 & 3.5.2):
    - Thu thập reaching definitions từ cả hai nhánh rẽ (if và else).
    - Trích xuất vị từ điều kiện rẽ nhánh (IfGuard, guard_condition).
    - control_dependencies liên kết đúng các nhánh với IfGuard.
    """
    code = (
        "def execute_dispatch(raw_input, is_admin):\n"
        "    if is_admin:\n"
        "        cmd = 'list_status'\n"
        "    else:\n"
        "        cmd = raw_input\n"
        "    os.system(f'tool_runner {cmd}')\n"
    )
    sink_line = 6

    res = slicer.slice_from_sink(code, sink_line, target_var="cmd")

    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.is_complete is True
    assert res.is_truncated is False
    assert res.sink_name == "os.system"

    # Both then-branch (line 3) and else-branch (line 5) must be preserved
    assert 3 in res.sliced_lines
    assert 5 in res.sliced_lines
    assert "cmd = 'list_status'" in res.sliced_code
    assert "cmd = raw_input" in res.sliced_code

    # Guard condition node (line 2) must be captured
    assert 2 in res.sliced_lines
    nodes_by_line = {node.line_number: node for node in res.nodes}
    guard_node = nodes_by_line[2]
    assert guard_node.node_type == "IfGuard"
    assert guard_node.dependency_reason == "guard_condition"
    assert "if is_admin:" in guard_node.code_snippet

    # Control dependencies: statements inside branches depend on the IfGuard (line 2)
    assert 2 in res.control_dependencies[3]
    assert 2 in res.control_dependencies[5]

    # Data dependencies: sink (line 6) reaches definitions from both branches (3 and 5)
    assert 3 in res.data_dependencies[6]
    assert 5 in res.data_dependencies[6]


# ---------------------------------------------------------------------------
# 4. test_sanitization_check
# ---------------------------------------------------------------------------

def test_sanitization_check(slicer: ASTSlicer) -> None:
    """Fixture 4: Lát cắt thu thập đầy đủ câu lệnh làm sạch (sanitizer) giữa source và sink.

    Mục tiêu (Section 3.1 & 3.5.2):
    - Trích xuất chính xác câu lệnh chứa hàm làm sạch/bảo vệ (ví dụ: shlex.quote, os.path.basename).
    - Biến đã làm sạch liên kết dữ liệu trực tiếp với tham số sink.
    - to_facts_prompt() xuất rõ ràng câu lệnh gọi hàm làm sạch để LLM thẩm định.
    - Vì sanitizer thuộc danh mục safe call đã biết, lát cắt đạt complete mà không bị cảnh báo hazard.
    """
    # 4a. OS Command Injection Sanitizer (CWE-78: shlex.quote)
    code_cwe78 = (
        "import shlex\n"
        "import subprocess\n"
        "\n"
        "def run_ping(target_host):\n"
        "    sanitized_host = shlex.quote(target_host)\n"
        "    subprocess.run(f'ping -c 1 {sanitized_host}', shell=True)\n"
    )
    res_cwe78 = slicer.slice_from_sink(code_cwe78, 6)

    assert res_cwe78.completeness_status == COMPLETENESS_COMPLETE
    assert res_cwe78.is_complete is True
    assert 5 in res_cwe78.sliced_lines
    assert 6 in res_cwe78.sliced_lines
    assert "sanitized_host = shlex.quote(target_host)" in res_cwe78.sliced_code

    # Verify data dependency: line 6 (subprocess.run) depends on line 5 (shlex.quote)
    assert 5 in res_cwe78.data_dependencies[6]
    assert 4 in res_cwe78.data_dependencies[5]

    # Facts prompt must clearly contain the sanitizer call
    facts = res_cwe78.to_facts_prompt()
    assert "shlex.quote" in facts
    assert "subprocess.run" in facts

    # 4b. Path Traversal Sanitizer (CWE-22: os.path.basename)
    code_cwe22 = (
        "import os\n"
        "\n"
        "def read_file(filename):\n"
        "    safe_name = os.path.basename(filename)\n"
        "    with open(safe_name, 'r') as f:\n"
        "        return f.read()\n"
    )
    res_cwe22 = slicer.slice_from_sink(code_cwe22, 5)

    assert res_cwe22.completeness_status == COMPLETENESS_COMPLETE
    assert 4 in res_cwe22.sliced_lines  # safe_name = os.path.basename(filename)
    assert 5 in res_cwe22.sliced_lines  # with open(safe_name, 'r') as f:
    assert 4 in res_cwe22.data_dependencies[5]
    assert "os.path.basename" in res_cwe22.to_facts_prompt()


# ---------------------------------------------------------------------------
# 5. test_attribute_and_call_chain
# ---------------------------------------------------------------------------

def test_attribute_and_call_chain(slicer: ASTSlicer) -> None:
    """Fixture 5: Truy vết data flow qua thuộc tính đối tượng (obj.attr) và chuỗi lời gọi hàm.

    Mục tiêu (Section 3.1 & 3.5.2):
    - Truy vết luồng dữ liệu qua chuỗi gọi hàm liên hoàn (chained method calls: raw.strip().lower()).
    - Truy vết thuộc tính đối tượng phức hợp (request.args.get(...) và self.query).
    - Liên kết dependency graph thông suốt từ sink ngược về thuộc tính/tham số ban đầu.
    """
    # 5a. Chained calls and attribute lookup on web request
    code_req = (
        "def handle_request(request):\n"
        "    raw_query = request.args.get('query')\n"
        "    clean_query = raw_query.strip().lower()\n"
        "    cursor.execute(clean_query)\n"
    )
    res_req = slicer.slice_from_sink(code_req, 4, target_var="clean_query")

    assert res_req.completeness_status == COMPLETENESS_COMPLETE
    assert res_req.is_complete is True
    assert res_req.sliced_lines == [1, 2, 3, 4]

    # Data dependency chain: 4 -> 3 -> 2 -> 1
    assert 3 in res_req.data_dependencies[4]
    assert 2 in res_req.data_dependencies[3]
    assert 1 in res_req.data_dependencies[2]

    nodes_by_line = {node.line_number: node for node in res_req.nodes}
    assert "clean_query" in nodes_by_line[3].variables_defined
    assert "raw_query" in nodes_by_line[3].variables_used
    assert "raw_query" in nodes_by_line[2].variables_defined
    assert "request" in nodes_by_line[2].variables_used

    # 5b. Object attribute assignment (self.query) in class method
    code_obj = (
        "class UserHandler:\n"
        "    def process(self, user_input):\n"
        "        self.query = user_input.strip()\n"
        "        sql = f'SELECT * FROM users WHERE name = {self.query}'\n"
        "        cursor.execute(sql)\n"
    )
    res_obj = slicer.slice_from_sink(code_obj, 5, target_var="sql")

    assert res_obj.completeness_status == COMPLETENESS_COMPLETE
    assert 2 in res_obj.sliced_lines  # def process(self, user_input)
    assert 3 in res_obj.sliced_lines  # self.query = user_input.strip()
    assert 4 in res_obj.sliced_lines  # sql = ...
    assert 5 in res_obj.sliced_lines  # cursor.execute(sql)

    assert 4 in res_obj.data_dependencies[5]
    assert 3 in res_obj.data_dependencies[4]
    assert 2 in res_obj.data_dependencies[3]


# ---------------------------------------------------------------------------
# 6. test_budget_partial_fallback
# ---------------------------------------------------------------------------

def test_budget_partial_fallback(slicer: ASTSlicer) -> None:
    """Fixture 6: Vượt quá ngân sách max_loop_iterations hoặc max_slice_lines, hệ thống
    trả về completeness_status='partial' an toàn mà không bị crash hay vòng lặp vô hạn.

    Mục tiêu (Section 3.1.4 & 3.1.5 & 3.5.2):
    - max_loop_iterations budget violation:
      Dừng an toàn khi vượt ngưỡng lặp, đánh dấu completeness_status='partial',
      is_truncated=True, reason='fixpoint_iteration_budget_exceeded'.
    - max_slice_lines budget violation:
      Cắt tỉa theo độ ưu tiên, bảo toàn sink bắt buộc, đánh dấu completeness_status='partial',
      is_truncated=True, reason='slice_line_budget_exceeded'.
    - Dynamic dispatch (getattr) & Syntax error:
      Fail-safe mà không ném unhandled exception làm crash pipeline.
    """
    # 6a. Loop fixpoint budget exhaustion (max_loop_iterations=1)
    code_loop = (
        "def loop_stress(val):\n"
        "    x = val\n"
        "    while True:\n"
        "        x = x + 1\n"
        "        y = x\n"
        "    cursor.execute(y)\n"
    )
    loop_slicer = ASTSlicer(max_loop_iterations=1)
    res_loop = loop_slicer.slice_from_sink(code_loop, 6, target_var="y")

    assert res_loop.completeness_status == COMPLETENESS_PARTIAL
    assert res_loop.is_complete is False
    assert res_loop.is_truncated is True
    assert "fixpoint_iteration_budget_exceeded" in res_loop.reason
    assert res_loop.truncation_reason == "fixpoint_iteration_budget_exceeded"

    # 6b. Physical line budget exhaustion (max_slice_lines=2)
    code_deep = (
        "def deep_chain(val):\n"
        "    a = val\n"
        "    b = a\n"
        "    c = b\n"
        "    d = c\n"
        "    e = d\n"
        "    cursor.execute(e)\n"
    )
    line_slicer = ASTSlicer(max_slice_lines=2)
    res_line = line_slicer.slice_from_sink(code_deep, 7, target_var="e")

    assert res_line.completeness_status == COMPLETENESS_PARTIAL
    assert res_line.is_complete is False
    assert res_line.is_truncated is True
    assert "slice_line_budget_exceeded" in res_line.reason
    assert res_line.truncation_reason == "slice_line_budget_exceeded"
    # Mandatory sink line (7) must be preserved despite strict budget
    assert 7 in res_line.sliced_lines
    assert len(res_line.sliced_lines) <= 2

    # 6c. Dynamic aliasing / dynamic dispatch fallback (getattr)
    code_dyn = (
        "def dynamic_handler(obj, method_name, payload):\n"
        "    handler = getattr(obj, method_name)\n"
        "    a = b = payload\n"
        "    handler(a)\n"
    )
    res_dyn = slicer.slice_from_sink(code_dyn, 4)

    assert res_dyn.completeness_status in [COMPLETENESS_PARTIAL, "unknown"]
    assert "dynamic_dispatch:getattr" in res_dyn.reason or "alias_escape" in res_dyn.reason
    assert not res_dyn.is_complete

    # 6d. Syntax error resilience (graceful handling, no unhandled crash)
    code_broken = (
        "def broken_syntax(val):\n"
        "    query = 'SELECT * FROM users WHERE id = ' + val\n"
        "    cursor.execute(query\n"
    )
    res_broken = slicer.slice_from_sink(code_broken, 3, target_var="query")

    assert res_broken.completeness_status == COMPLETENESS_FAILED
    assert "syntax_error" in res_broken.reason
    assert res_broken.nodes == []
    assert res_broken.sliced_lines == []


# ---------------------------------------------------------------------------
# Aliases matching Phuong_an_2.md Section 3.5.2 named fixtures
# ---------------------------------------------------------------------------

def test_slice_reassignment(slicer: ASTSlicer) -> None:
    """Design doc Section 3.5.2 fixture alias: Reassignment & dead code elimination."""
    test_direct_taint(slicer)


def test_slice_branch_merging(slicer: ASTSlicer) -> None:
    """Design doc Section 3.5.2 fixture alias: Branch merging & IfGuard extraction."""
    test_branch_merge(slicer)


def test_slice_loop_dependency(slicer: ASTSlicer) -> None:
    """Design doc Section 3.5.2 fixture alias: Loop dependency fixpoint."""
    test_loop_fixpoint(slicer)


def test_slice_cwe_sanitizers(slicer: ASTSlicer) -> None:
    """Design doc Section 3.5.2 fixture alias: CWE-specific sanitizers."""
    test_sanitization_check(slicer)


def test_slice_dynamic_aliasing_fallback(slicer: ASTSlicer) -> None:
    """Design doc Section 3.5.2 fixture alias: Dynamic aliasing & getattr fallback."""
    code_dyn = (
        "def dynamic_handler(obj, method_name, payload):\n"
        "    handler = getattr(obj, method_name)\n"
        "    a = b = payload\n"
        "    handler(a)\n"
    )
    res = slicer.slice_from_sink(code_dyn, 4)
    assert res.completeness_status in [COMPLETENESS_PARTIAL, "unknown"]
    assert "alias_escape" in res.reason or "dynamic_dispatch" in res.reason


def test_slice_syntax_error_resilience(slicer: ASTSlicer) -> None:
    """Design doc Section 3.5.2 fixture alias: Syntax error resilience."""
    broken = "def broken(val):\n    cursor.execute(val\n"
    res = slicer.slice_from_sink(broken, 2)
    assert res.completeness_status == COMPLETENESS_FAILED
    assert "syntax_error" in res.reason


# ---------------------------------------------------------------------------
# 7. test_abstract_sink_categories
# ---------------------------------------------------------------------------

def test_abstract_sink_categories_structure() -> None:
    """Verify that ABSTRACT_SINK_CATEGORIES defines all standard groups."""
    expected_categories = {
        "DATABASE_EXECUTION",
        "COMMAND_EXECUTION",
        "DYNAMIC_EVALUATION",
        "SERIALIZATION",
        "NETWORK_SSRF",
        "FILE_IO",
        "RESPONSE_RENDER",
        "EXCEPTION_HANDLING",
        "HARDCODED_CREDENTIALS",
        "ACCESS_CONTROL",
        "WEAK_HASHING",
        "INSECURE_RANDOMNESS",
        "XPATH_INJECTION",
        "COOKIE_SECURITY",
        "LDAP_INJECTION",
        "OPEN_REDIRECT",
        "XML_EXTERNAL_ENTITY",
    }
    assert set(ABSTRACT_SINK_CATEGORIES.keys()) == expected_categories

    # Verify SINK_CALL_SIGNATURES is synthesized from ABSTRACT_SINK_CATEGORIES
    expected_signatures = tuple(
        sig for sigs in ABSTRACT_SINK_CATEGORIES.values() for sig in sigs
    )
    assert SINK_CALL_SIGNATURES == expected_signatures

    # Spot-check critical members for each category
    assert "cursor.execute" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]
    assert "connection.execute" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]
    assert "session.execute" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]
    assert "raw" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]
    assert "execute" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]
    assert "executemany" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]
    assert "select" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]
    assert "filter" in ABSTRACT_SINK_CATEGORIES["DATABASE_EXECUTION"]

    assert "subprocess.*" in ABSTRACT_SINK_CATEGORIES["COMMAND_EXECUTION"]
    assert "subprocess.run" in ABSTRACT_SINK_CATEGORIES["COMMAND_EXECUTION"]
    assert "os.system" in ABSTRACT_SINK_CATEGORIES["COMMAND_EXECUTION"]
    assert "os.popen" in ABSTRACT_SINK_CATEGORIES["COMMAND_EXECUTION"]
    assert "pty.spawn" in ABSTRACT_SINK_CATEGORIES["COMMAND_EXECUTION"]
    assert "shlex" in ABSTRACT_SINK_CATEGORIES["COMMAND_EXECUTION"]

    assert "eval" in ABSTRACT_SINK_CATEGORIES["DYNAMIC_EVALUATION"]
    assert "exec" in ABSTRACT_SINK_CATEGORIES["DYNAMIC_EVALUATION"]
    assert "compile" in ABSTRACT_SINK_CATEGORIES["DYNAMIC_EVALUATION"]

    assert "pickle.*" in ABSTRACT_SINK_CATEGORIES["SERIALIZATION"]
    assert "pickle.loads" in ABSTRACT_SINK_CATEGORIES["SERIALIZATION"]
    assert "yaml.load" in ABSTRACT_SINK_CATEGORIES["SERIALIZATION"]
    assert "yaml.unsafe_load" in ABSTRACT_SINK_CATEGORIES["SERIALIZATION"]
    assert "jsonpickle.decode" in ABSTRACT_SINK_CATEGORIES["SERIALIZATION"]
    assert "marshal.loads" in ABSTRACT_SINK_CATEGORIES["SERIALIZATION"]
    assert "shelve.open" in ABSTRACT_SINK_CATEGORIES["SERIALIZATION"]

    assert "requests.*" in ABSTRACT_SINK_CATEGORIES["NETWORK_SSRF"]
    assert "requests.get" in ABSTRACT_SINK_CATEGORIES["NETWORK_SSRF"]
    assert "urllib.request.*" in ABSTRACT_SINK_CATEGORIES["NETWORK_SSRF"]
    assert "urllib.request.urlopen" in ABSTRACT_SINK_CATEGORIES["NETWORK_SSRF"]
    assert "httpx.*" in ABSTRACT_SINK_CATEGORIES["NETWORK_SSRF"]
    assert "aiohttp.ClientSession" in ABSTRACT_SINK_CATEGORIES["NETWORK_SSRF"]
    assert "urllib3.PoolManager" in ABSTRACT_SINK_CATEGORIES["NETWORK_SSRF"]

    assert "open" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "os.open" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "os.remove" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "shutil.*" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "pathlib.Path" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "flask.send_file" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "send_file" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "tarfile.open" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "tarfile.TarFile.extractall" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "zipfile.ZipFile" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "zipfile.ZipFile.extractall" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "extractall" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "os.walk" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]
    assert "shutil.unpack_archive" in ABSTRACT_SINK_CATEGORIES["FILE_IO"]

    assert "flask.render_template" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]
    assert "render_template" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]
    assert "render_template_string" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]
    assert "Markup" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]
    assert "mark_safe" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]
    assert "HttpResponse" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]
    assert "Response" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]
    assert "flash" in ABSTRACT_SINK_CATEGORIES["RESPONSE_RENDER"]

    assert "traceback.format_exc" in ABSTRACT_SINK_CATEGORIES["EXCEPTION_HANDLING"]
    assert "traceback.print_exc" in ABSTRACT_SINK_CATEGORIES["EXCEPTION_HANDLING"]
    assert "format_error" in ABSTRACT_SINK_CATEGORIES["EXCEPTION_HANDLING"]
    assert "sys.exc_info" in ABSTRACT_SINK_CATEGORIES["EXCEPTION_HANDLING"]

    assert "SECRET_KEY" in ABSTRACT_SINK_CATEGORIES["HARDCODED_CREDENTIALS"]
    assert "PASSWORD" in ABSTRACT_SINK_CATEGORIES["HARDCODED_CREDENTIALS"]
    assert "API_KEY" in ABSTRACT_SINK_CATEGORIES["HARDCODED_CREDENTIALS"]
    assert "TOKEN" in ABSTRACT_SINK_CATEGORIES["HARDCODED_CREDENTIALS"]
    assert "PRIVATE_KEY" in ABSTRACT_SINK_CATEGORIES["HARDCODED_CREDENTIALS"]

    assert "get_object_or_404" in ABSTRACT_SINK_CATEGORIES["ACCESS_CONTROL"]
    assert "objects.get" in ABSTRACT_SINK_CATEGORIES["ACCESS_CONTROL"]
    assert "login_required" in ABSTRACT_SINK_CATEGORIES["ACCESS_CONTROL"]
    assert "authenticate" in ABSTRACT_SINK_CATEGORIES["ACCESS_CONTROL"]

    # WEAK_HASHING (CWE-327, CWE-328)
    for sig in (
        "hashlib.md5",
        "hashlib.sha1",
        "hashlib.new",
        "Crypto.Hash.MD5",
        "Crypto.Hash.SHA",
        "Cryptodome.Hash.MD5",
        "Cryptodome.Hash.SHA",
        "md5",
        "sha1",
        "sha224",
        "ripemd160",
    ):
        assert sig in ABSTRACT_SINK_CATEGORIES["WEAK_HASHING"]

    # INSECURE_RANDOMNESS (CWE-330)
    for sig in (
        "random.random",
        "random.choice",
        "random.randint",
        "random.randrange",
        "random.sample",
        "random.getrandbits",
        "random.uniform",
        "random.seed",
        "random.triangular",
        "random.betavariate",
        "random.expovariate",
        "random.gammavariate",
        "random.gauss",
    ):
        assert sig in ABSTRACT_SINK_CATEGORIES["INSECURE_RANDOMNESS"]

    # XPATH_INJECTION (CWE-643)
    for sig in (
        "xpath",
        "find",
        "findall",
        "findtext",
        "iterfind",
        "getiterator",
        "etree.XPath",
        "lxml.etree.XPath",
        "eval_xpath",
        "xpath_eval",
    ):
        assert sig in ABSTRACT_SINK_CATEGORIES["XPATH_INJECTION"]

    # COOKIE_SECURITY (CWE-614, CWE-1004)
    for sig in (
        "set_cookie",
        "response.set_cookie",
        "set_signed_cookie",
    ):
        assert sig in ABSTRACT_SINK_CATEGORIES["COOKIE_SECURITY"]

    # LDAP_INJECTION (CWE-90)
    for sig in (
        "ldap.search",
        "ldap.search_s",
        "ldap3.Connection.search",
        "connection.search",
        "search_s",
    ):
        assert sig in ABSTRACT_SINK_CATEGORIES["LDAP_INJECTION"]

    # OPEN_REDIRECT (CWE-601)
    for sig in (
        "redirect",
        "flask.redirect",
        "django.shortcuts.redirect",
        "HttpResponseRedirect",
        "HttpResponsePermanentRedirect",
    ):
        assert sig in ABSTRACT_SINK_CATEGORIES["OPEN_REDIRECT"]

    # XML_EXTERNAL_ENTITY (CWE-611)
    for sig in (
        "xml.etree.ElementTree.parse",
        "xml.etree.ElementTree.fromstring",
        "xml.dom.minidom.parse",
        "xml.dom.minidom.parseString",
        "lxml.etree.parse",
        "lxml.etree.fromstring",
        "xml.sax.parse",
    ):
        assert sig in ABSTRACT_SINK_CATEGORIES["XML_EXTERNAL_ENTITY"]


def test_get_sink_category_resolution(slicer: ASTSlicer) -> None:
    """Verify get_sink_category resolves signatures and dotted calls correctly."""
    # Module-level get_sink_category
    assert get_sink_category("cursor.execute") == "DATABASE_EXECUTION"
    assert get_sink_category("connection.execute") == "DATABASE_EXECUTION"
    assert get_sink_category("db.cursor.execute") == "DATABASE_EXECUTION"
    assert get_sink_category("raw") == "DATABASE_EXECUTION"

    assert get_sink_category("subprocess.run") == "COMMAND_EXECUTION"
    assert get_sink_category("os.system") == "COMMAND_EXECUTION"

    assert get_sink_category("eval") == "DYNAMIC_EVALUATION"
    assert get_sink_category("exec") == "DYNAMIC_EVALUATION"

    assert get_sink_category("pickle.loads") == "SERIALIZATION"
    assert get_sink_category("yaml.unsafe_load") == "SERIALIZATION"

    assert get_sink_category("requests.get") == "NETWORK_SSRF"
    assert get_sink_category("urllib.request.urlopen") == "NETWORK_SSRF"
    assert get_sink_category("httpx.get") == "NETWORK_SSRF"

    assert get_sink_category("open") == "FILE_IO"
    assert get_sink_category("flask.send_file") == "FILE_IO"
    assert get_sink_category("send_file") == "FILE_IO"
    assert get_sink_category("tarfile.TarFile.extractall") == "FILE_IO"
    assert get_sink_category("zipfile.ZipFile.extractall") == "FILE_IO"
    assert get_sink_category("extractall") == "FILE_IO"
    assert get_sink_category("os.walk") == "FILE_IO"
    assert get_sink_category("shutil.unpack_archive") == "FILE_IO"

    assert get_sink_category("flask.render_template") == "RESPONSE_RENDER"
    assert get_sink_category("render_template_string") == "RESPONSE_RENDER"
    assert get_sink_category("Markup") == "RESPONSE_RENDER"
    assert get_sink_category("HttpResponse") == "RESPONSE_RENDER"
    assert get_sink_category("Response") == "RESPONSE_RENDER"
    assert get_sink_category("Template") == "RESPONSE_RENDER"

    assert get_sink_category("traceback.format_exc") == "EXCEPTION_HANDLING"
    assert get_sink_category("sys.exc_info") == "EXCEPTION_HANDLING"

    # New 7 categories resolution
    assert get_sink_category("hashlib.md5") == "WEAK_HASHING"
    assert get_sink_category("hashlib.new") == "WEAK_HASHING"
    assert get_sink_category("sha224") == "WEAK_HASHING"
    assert get_sink_category("ripemd160") == "WEAK_HASHING"
    assert get_sink_category("Crypto.Hash.SHA") == "WEAK_HASHING"
    assert get_sink_category("random.randint") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.choice") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.triangular") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.betavariate") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.expovariate") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.gammavariate") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.gauss") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.uniform") == "INSECURE_RANDOMNESS"
    assert get_sink_category("xpath") == "XPATH_INJECTION"
    assert get_sink_category("findtext") == "XPATH_INJECTION"
    assert get_sink_category("iterfind") == "XPATH_INJECTION"
    assert get_sink_category("getiterator") == "XPATH_INJECTION"
    assert get_sink_category("xpath_eval") == "XPATH_INJECTION"
    assert get_sink_category("etree.XPath") == "XPATH_INJECTION"
    assert get_sink_category("set_cookie") == "COOKIE_SECURITY"
    assert get_sink_category("response.set_cookie") == "COOKIE_SECURITY"
    assert get_sink_category("ldap.search") == "LDAP_INJECTION"
    assert get_sink_category("connection.search") == "LDAP_INJECTION"
    assert get_sink_category("redirect") == "OPEN_REDIRECT"
    assert get_sink_category("flask.redirect") == "OPEN_REDIRECT"
    assert get_sink_category("xml.etree.ElementTree.parse") == "XML_EXTERNAL_ENTITY"
    assert get_sink_category("lxml.etree.parse") == "XML_EXTERNAL_ENTITY"

    # Static method on ASTSlicer
    assert ASTSlicer.get_sink_category("cursor.execute") == "DATABASE_EXECUTION"
    assert ASTSlicer.get_sink_category("hashlib.md5") == "WEAK_HASHING"
    assert slicer.get_sink_category("os.system") == "COMMAND_EXECUTION"
    assert slicer.get_sink_category("flask.redirect") == "OPEN_REDIRECT"

    # Non-sink calls and safe calls
    assert get_sink_category("unknown_function") is None
    assert get_sink_category("") is None
    assert get_sink_category("get") is None
    assert get_sink_category("len") is None


def test_slice_result_sink_category(slicer: ASTSlicer) -> None:
    """Verify SliceResult exposes sink_category property correctly."""
    code = (
        "def query(uid):\n"
        "    sql = f'SELECT {uid}'\n"
        "    cursor.execute(sql)\n"
    )
    res = slicer.slice_from_sink(code, 3, "sql")
    assert res.sink_name == "cursor.execute"
    assert res.sink_category == "DATABASE_EXECUTION"


def test_expanded_10_cwe_sink_categories(slicer: ASTSlicer) -> None:
    """Verify sink category resolution across all 10 canonical CWE groups."""
    # CWE-89
    assert get_sink_category("execute") == "DATABASE_EXECUTION"
    assert get_sink_category("executemany") == "DATABASE_EXECUTION"
    assert get_sink_category("raw") == "DATABASE_EXECUTION"
    assert get_sink_category("select") == "DATABASE_EXECUTION"
    assert get_sink_category("filter") == "DATABASE_EXECUTION"
    assert get_sink_category("objects.filter") == "DATABASE_EXECUTION"
    assert get_sink_category("query.filter") == "DATABASE_EXECUTION"
    assert get_sink_category("User.objects.raw") == "DATABASE_EXECUTION"

    # CWE-78
    assert get_sink_category("subprocess.run") == "COMMAND_EXECUTION"
    assert get_sink_category("subprocess.check_output") == "COMMAND_EXECUTION"
    assert get_sink_category("subprocess.Popen") == "COMMAND_EXECUTION"
    assert get_sink_category("os.system") == "COMMAND_EXECUTION"
    assert get_sink_category("os.popen") == "COMMAND_EXECUTION"
    assert get_sink_category("pty.spawn") == "COMMAND_EXECUTION"
    assert get_sink_category("shlex.split") == "COMMAND_EXECUTION"

    # CWE-22
    assert get_sink_category("open") == "FILE_IO"
    assert get_sink_category("os.open") == "FILE_IO"
    assert get_sink_category("os.remove") == "FILE_IO"
    assert get_sink_category("shutil.rmtree") == "FILE_IO"
    assert get_sink_category("shutil.copy") == "FILE_IO"
    assert get_sink_category("pathlib.Path") == "FILE_IO"
    assert get_sink_category("send_file") == "FILE_IO"
    assert get_sink_category("tarfile.open") == "FILE_IO"
    assert get_sink_category("zipfile.ZipFile") == "FILE_IO"

    # CWE-502
    assert get_sink_category("pickle.loads") == "SERIALIZATION"
    assert get_sink_category("pickle.load") == "SERIALIZATION"
    assert get_sink_category("yaml.load") == "SERIALIZATION"
    assert get_sink_category("yaml.unsafe_load") == "SERIALIZATION"
    assert get_sink_category("jsonpickle.decode") == "SERIALIZATION"
    assert get_sink_category("marshal.loads") == "SERIALIZATION"
    assert get_sink_category("shelve.open") == "SERIALIZATION"

    # CWE-918
    assert get_sink_category("requests.get") == "NETWORK_SSRF"
    assert get_sink_category("requests.post") == "NETWORK_SSRF"
    assert get_sink_category("urllib.request.urlopen") == "NETWORK_SSRF"
    assert get_sink_category("httpx.get") == "NETWORK_SSRF"
    assert get_sink_category("httpx.post") == "NETWORK_SSRF"
    assert get_sink_category("aiohttp.ClientSession") == "NETWORK_SSRF"
    assert get_sink_category("urllib3.PoolManager") == "NETWORK_SSRF"

    # CWE-79
    assert get_sink_category("Markup") == "RESPONSE_RENDER"
    assert get_sink_category("mark_safe") == "RESPONSE_RENDER"
    assert get_sink_category("render_template") == "RESPONSE_RENDER"
    assert get_sink_category("render_template_string") == "RESPONSE_RENDER"
    assert get_sink_category("HttpResponse") == "RESPONSE_RENDER"
    assert get_sink_category("Response") == "RESPONSE_RENDER"
    assert get_sink_category("flash") == "RESPONSE_RENDER"

    # CWE-798
    assert get_sink_category("SECRET_KEY") == "HARDCODED_CREDENTIALS"
    assert get_sink_category("PASSWORD") == "HARDCODED_CREDENTIALS"
    assert get_sink_category("API_KEY") == "HARDCODED_CREDENTIALS"
    assert get_sink_category("TOKEN") == "HARDCODED_CREDENTIALS"
    assert get_sink_category("PRIVATE_KEY") == "HARDCODED_CREDENTIALS"

    # CWE-209
    assert get_sink_category("traceback.format_exc") == "EXCEPTION_HANDLING"
    assert get_sink_category("traceback.print_exc") == "EXCEPTION_HANDLING"
    assert get_sink_category("format_error") == "EXCEPTION_HANDLING"
    assert get_sink_category("sys.exc_info") == "EXCEPTION_HANDLING"

    # CWE-287 / CWE-639
    assert get_sink_category("get_object_or_404") == "ACCESS_CONTROL"
    assert get_sink_category("objects.get") == "ACCESS_CONTROL"
    assert get_sink_category("query.get") == "ACCESS_CONTROL"
    assert get_sink_category("filter_by") == "ACCESS_CONTROL"
    assert get_sink_category("find_by_id") == "ACCESS_CONTROL"
    assert get_sink_category("authenticate") == "ACCESS_CONTROL"
    assert get_sink_category("login_required") == "ACCESS_CONTROL"


def test_static_secret_assignment_slice(slicer: ASTSlicer) -> None:
    """Verify static string assignment slicing for CWE-798."""
    code = (
        "SECRET_KEY = 'hardcoded-top-secret-token'\n"
        "DEBUG = True\n"
    )
    res = slicer.slice_from_sink(code, 1, target_var="SECRET_KEY")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_name == "SECRET_KEY"
    assert res.sink_category == "HARDCODED_CREDENTIALS"
    assert res.sliced_lines == [1]


def test_orm_filter_and_select_sinks(slicer: ASTSlicer) -> None:
    """Verify slicing on ORM filter and archive traversal sinks."""
    code = (
        "def query_user(user_id):\n"
        "    res = User.objects.filter(id=user_id)\n"
        "    return res\n"
    )
    res = slicer.slice_from_sink(code, 2, target_var="user_id")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "DATABASE_EXECUTION"
    assert res.sliced_lines == [1, 2]


# ---------------------------------------------------------------------------
# Tests for 7 new Sink categories (expand-ast-sinks)
# ---------------------------------------------------------------------------

def test_expanded_7_new_sink_categories(slicer: ASTSlicer) -> None:
    """Verify sink category resolution across all 7 newly added groups."""
    # 1. WEAK_HASHING (CWE-327, CWE-328)
    assert get_sink_category("hashlib.md5") == "WEAK_HASHING"
    assert get_sink_category("hashlib.sha1") == "WEAK_HASHING"
    assert get_sink_category("Crypto.Hash.MD5") == "WEAK_HASHING"
    assert get_sink_category("Crypto.Hash.SHA") == "WEAK_HASHING"
    assert get_sink_category("Cryptodome.Hash.MD5") == "WEAK_HASHING"
    assert get_sink_category("Cryptodome.Hash.SHA") == "WEAK_HASHING"
    assert get_sink_category("md5") == "WEAK_HASHING"
    assert get_sink_category("sha1") == "WEAK_HASHING"

    # 2. INSECURE_RANDOMNESS (CWE-330)
    assert get_sink_category("random.random") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.choice") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.randint") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.randrange") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.sample") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.getrandbits") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.uniform") == "INSECURE_RANDOMNESS"
    assert get_sink_category("random.seed") == "INSECURE_RANDOMNESS"

    # 3. XPATH_INJECTION (CWE-643)
    assert get_sink_category("xpath") == "XPATH_INJECTION"
    assert get_sink_category("find") == "XPATH_INJECTION"
    assert get_sink_category("findall") == "XPATH_INJECTION"
    assert get_sink_category("etree.XPath") == "XPATH_INJECTION"
    assert get_sink_category("lxml.etree.XPath") == "XPATH_INJECTION"
    assert get_sink_category("eval_xpath") == "XPATH_INJECTION"
    assert get_sink_category("tree.xpath") == "XPATH_INJECTION"
    assert get_sink_category("element.xpath") == "XPATH_INJECTION"

    # 4. COOKIE_SECURITY (CWE-614, CWE-1004)
    assert get_sink_category("set_cookie") == "COOKIE_SECURITY"
    assert get_sink_category("response.set_cookie") == "COOKIE_SECURITY"
    assert get_sink_category("set_signed_cookie") == "COOKIE_SECURITY"
    assert get_sink_category("resp.set_cookie") == "COOKIE_SECURITY"

    # 5. LDAP_INJECTION (CWE-90)
    assert get_sink_category("ldap.search") == "LDAP_INJECTION"
    assert get_sink_category("ldap.search_s") == "LDAP_INJECTION"
    assert get_sink_category("ldap3.Connection.search") == "LDAP_INJECTION"
    assert get_sink_category("connection.search") == "LDAP_INJECTION"
    assert get_sink_category("conn.search") == "LDAP_INJECTION"
    assert get_sink_category("client.search") == "LDAP_INJECTION"
    assert get_sink_category("helpers.ldap.get_connection") == "LDAP_INJECTION"
    assert get_sink_category("search_s") == "LDAP_INJECTION"
    assert get_sink_category("conn.search_s") == "LDAP_INJECTION"

    # 6. OPEN_REDIRECT (CWE-601)
    assert get_sink_category("redirect") == "OPEN_REDIRECT"
    assert get_sink_category("flask.redirect") == "OPEN_REDIRECT"
    assert get_sink_category("django.shortcuts.redirect") == "OPEN_REDIRECT"
    assert get_sink_category("HttpResponseRedirect") == "OPEN_REDIRECT"
    assert get_sink_category("HttpResponsePermanentRedirect") == "OPEN_REDIRECT"

    # 7. XML_EXTERNAL_ENTITY (CWE-611)
    assert get_sink_category("xml.etree.ElementTree.parse") == "XML_EXTERNAL_ENTITY"
    assert get_sink_category("xml.etree.ElementTree.fromstring") == "XML_EXTERNAL_ENTITY"
    assert get_sink_category("xml.dom.minidom.parse") == "XML_EXTERNAL_ENTITY"
    assert get_sink_category("xml.dom.minidom.parseString") == "XML_EXTERNAL_ENTITY"
    assert get_sink_category("lxml.etree.parse") == "XML_EXTERNAL_ENTITY"
    assert get_sink_category("lxml.etree.fromstring") == "XML_EXTERNAL_ENTITY"
    assert get_sink_category("xml.sax.parse") == "XML_EXTERNAL_ENTITY"


def test_weak_hashing_slice(slicer: ASTSlicer) -> None:
    """Verify backward slicing on weak hashing sinks (CWE-327/328)."""
    code = (
        "def hash_password(password):\n"
        "    salt = 'fixed_salt'\n"
        "    data = password + salt\n"
        "    digest = hashlib.md5(data.encode())\n"
        "    return digest.hexdigest()\n"
    )
    res = slicer.slice_from_sink(code, 4, target_var="data")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "WEAK_HASHING"
    assert 4 in res.sliced_lines
    assert 3 in res.sliced_lines
    assert 1 in res.sliced_lines


def test_open_redirect_slice(slicer: ASTSlicer) -> None:
    """Verify backward slicing on open redirect sinks (CWE-601)."""
    code = (
        "def handle_login(req):\n"
        "    target = req.args.get('next', '/')\n"
        "    return flask.redirect(target)\n"
    )
    res = slicer.slice_from_sink(code, 3, target_var="target")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "OPEN_REDIRECT"
    assert res.sliced_lines == [1, 2, 3]


def test_xpath_injection_slice(slicer: ASTSlicer) -> None:
    """Verify backward slicing on XPath injection sinks (CWE-643)."""
    code = (
        "def query_xml(user_val):\n"
        "    expr = f'//user[name=\"{user_val}\"]'\n"
        "    results = root.xpath(expr)\n"
        "    return results\n"
    )
    res = slicer.slice_from_sink(code, 3, target_var="expr")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "XPATH_INJECTION"
    assert res.sliced_lines == [1, 2, 3]


def test_ldap_injection_slice(slicer: ASTSlicer) -> None:
    """Verify backward slicing on LDAP injection sinks (CWE-90)."""
    code = (
        "def ldap_auth(username):\n"
        "    search_filter = f'(uid={username})'\n"
        "    connection.search(search_filter)\n"
    )
    res = slicer.slice_from_sink(code, 3, target_var="search_filter")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "LDAP_INJECTION"
    assert res.sliced_lines == [1, 2, 3]


def test_xml_external_entity_slice(slicer: ASTSlicer) -> None:
    """Verify backward slicing on XXE sinks (CWE-611)."""
    code = (
        "def parse_doc(file_path):\n"
        "    target = file_path\n"
        "    doc = lxml.etree.parse(target)\n"
        "    return doc\n"
    )
    res = slicer.slice_from_sink(code, 3, target_var="target")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "XML_EXTERNAL_ENTITY"
    assert res.sliced_lines == [1, 2, 3]


def test_cookie_security_slice(slicer: ASTSlicer) -> None:
    """Verify backward slicing on Cookie sinks (CWE-614/1004)."""
    code = (
        "def set_auth_token(resp, token):\n"
        "    cookie_val = token\n"
        "    resp.set_cookie('auth', cookie_val)\n"
    )
    res = slicer.slice_from_sink(code, 3, target_var="cookie_val")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "COOKIE_SECURITY"
    assert res.sliced_lines == [1, 2, 3]


def test_insecure_randomness_slice(slicer: ASTSlicer) -> None:
    """Verify backward slicing on insecure randomness sinks (CWE-330)."""
    code = (
        "def generate_pin(seed_val):\n"
        "    random.seed(seed_val)\n"
        "    pin = random.randint(1000, 9999)\n"
        "    return pin\n"
    )
    res = slicer.slice_from_sink(code, 3, target_var="pin")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "INSECURE_RANDOMNESS"


# ---------------------------------------------------------------------------
# Inter-procedural Call-Site Sink Anchoring Tests
# ---------------------------------------------------------------------------

def test_interprocedural_sink_anchoring_single_hop(slicer: ASTSlicer) -> None:
    """Verify candidate sink anchoring at call-site of a wrapper function calling a primitive sink."""
    code = (
        "def execute_sql(query):\n"
        "    cursor.execute(query)\n"
        "\n"
        "def handle_request(req):\n"
        "    user_data = req.get('data')\n"
        "    execute_sql(user_data)\n"
    )

    # 1. find_call_site_sink_anchors identifies line 6 (execute_sql(user_data))
    call_sites = find_call_site_sink_anchors(code)
    assert len(call_sites) == 1
    cs = call_sites[0]
    assert cs.line_number == 6
    assert cs.call_name == "execute_sql"
    assert cs.target_variable == "user_data"
    assert cs.sink_category == "DATABASE_EXECUTION"
    assert cs.is_interprocedural is True
    assert cs.wrapper_function == "execute_sql"

    # 2. find_sink_anchors includes both primitive sink at line 2 and call-site at line 6
    anchors = find_sink_anchors(code)
    lines = [a.line_number for a in anchors]
    assert 2 in lines  # cursor.execute
    assert 6 in lines  # execute_sql

    # 3. slice_from_sink on the call-site produces complete backward slice
    res = slicer.slice_from_sink(code, 6, target_var="user_data")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_name == "execute_sql"
    assert res.sink_category == "DATABASE_EXECUTION"
    assert res.sliced_lines == [4, 5, 6]
    assert "user_data = req.get('data')" in res.sliced_code
    assert "execute_sql(user_data)" in res.sliced_code


def test_interprocedural_sink_anchoring_multi_hop(slicer: ASTSlicer) -> None:
    """Verify transitive multi-hop wrapper forwarding parameters to call-sites."""
    code = (
        "def deep_sink(cmd):\n"
        "    os.system(cmd)\n"
        "\n"
        "def mid_layer(action):\n"
        "    deep_sink(action)\n"
        "\n"
        "def controller(user_input):\n"
        "    payload = 'prefix_' + user_input\n"
        "    mid_layer(payload)\n"
    )

    call_sites = find_call_site_sink_anchors(code)
    assert len(call_sites) >= 2
    # Check that line 9 (mid_layer(payload)) is captured
    site_lines = {cs.line_number: cs for cs in call_sites}
    assert 5 in site_lines  # deep_sink(action)
    assert 9 in site_lines  # mid_layer(payload)

    cs_top = site_lines[9]
    assert cs_top.call_name == "mid_layer"
    assert cs_top.target_variable == "payload"
    assert cs_top.sink_category == "COMMAND_EXECUTION"
    assert cs_top.is_interprocedural is True

    # Slicing from line 9 captures backward dataflow to user_input
    res = slicer.slice_from_sink(code, 9, target_var="payload")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "COMMAND_EXECUTION"
    assert res.sliced_lines == [7, 8, 9]
    assert "payload = 'prefix_' + user_input" in res.sliced_code


def test_interprocedural_sink_anchoring_method(slicer: ASTSlicer) -> None:
    """Verify method wrapper on class instance binds receiver and correctly maps arguments."""
    code = (
        "class SafeExecutor:\n"
        "    def run_eval(self, expr):\n"
        "        return eval(expr)\n"
        "\n"
        "def run_job(raw_expr):\n"
        "    runner = SafeExecutor()\n"
        "    runner.run_eval(raw_expr)\n"
    )

    call_sites = find_call_site_sink_anchors(code)
    assert len(call_sites) >= 1
    site = [cs for cs in call_sites if cs.line_number == 7][0]
    assert site.target_variable == "raw_expr"
    assert site.sink_category == "DYNAMIC_EVALUATION"
    assert site.is_interprocedural is True

    # Slicing from line 7 traces backward
    res = slicer.slice_from_sink(code, 7, target_var="raw_expr")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "DYNAMIC_EVALUATION"
    assert 5 in res.sliced_lines
    assert 7 in res.sliced_lines


def test_interprocedural_sink_anchoring_keyword_args(slicer: ASTSlicer) -> None:
    """Verify wrapper forwarding via keyword arguments."""
    code = (
        "def perform_query(timeout=30, query=None):\n"
        "    cursor.execute(query)\n"
        "\n"
        "def api_endpoint(request_sql):\n"
        "    perform_query(query=request_sql, timeout=10)\n"
    )

    call_sites = find_call_site_sink_anchors(code)
    assert len(call_sites) == 1
    assert call_sites[0].line_number == 5
    assert call_sites[0].target_variable == "request_sql"
    assert call_sites[0].sink_category == "DATABASE_EXECUTION"


def test_sink_anchor_unpacking() -> None:
    """Verify SinkAnchor backward-compatible tuple unpacking."""
    anchor = SinkAnchor(
        line_number=42,
        call_name="custom_exec",
        target_variable="cmd_str",
        sink_category="COMMAND_EXECUTION",
        is_interprocedural=True,
    )
    lineno, target = anchor
    assert lineno == 42
    assert target == "cmd_str"
    assert anchor[0] == 42
    assert anchor[1] == "cmd_str"


def test_heuristic_sink_constants() -> None:
    """Verify HEURISTIC_SINK_SUFFIXES and HEURISTIC_SINK_OBJECT_PREFIXES structure."""
    assert "DESERIALIZATION" in HEURISTIC_SINK_SUFFIXES
    assert "DATABASE_EXECUTION" in HEURISTIC_SINK_SUFFIXES
    assert "COMMAND_EXECUTION" in HEURISTIC_SINK_SUFFIXES
    assert "PATH_TRAVERSAL" in HEURISTIC_SINK_SUFFIXES

    assert ".loads" in HEURISTIC_SINK_SUFFIXES["DESERIALIZATION"]
    assert ".unserialize" in HEURISTIC_SINK_SUFFIXES["DESERIALIZATION"]
    assert ".unpickle" in HEURISTIC_SINK_SUFFIXES["DESERIALIZATION"]
    assert ".decode_payload" in HEURISTIC_SINK_SUFFIXES["DESERIALIZATION"]

    assert ".execute" in HEURISTIC_SINK_SUFFIXES["DATABASE_EXECUTION"]
    assert ".raw_exec" in HEURISTIC_SINK_SUFFIXES["DATABASE_EXECUTION"]
    assert ".raw_query" in HEURISTIC_SINK_SUFFIXES["DATABASE_EXECUTION"]
    assert ".as_sql" in HEURISTIC_SINK_SUFFIXES["DATABASE_EXECUTION"]

    assert ".call" in HEURISTIC_SINK_SUFFIXES["COMMAND_EXECUTION"]
    assert ".run_cmd" in HEURISTIC_SINK_SUFFIXES["COMMAND_EXECUTION"]
    assert ".exec_cmd" in HEURISTIC_SINK_SUFFIXES["COMMAND_EXECUTION"]
    assert ".format_cmd" in HEURISTIC_SINK_SUFFIXES["COMMAND_EXECUTION"]
    assert ".spawn" in HEURISTIC_SINK_SUFFIXES["COMMAND_EXECUTION"]

    assert ".joinpath" in HEURISTIC_SINK_SUFFIXES["PATH_TRAVERSAL"]
    assert ".open_file" in HEURISTIC_SINK_SUFFIXES["PATH_TRAVERSAL"]
    assert ".get_file" in HEURISTIC_SINK_SUFFIXES["PATH_TRAVERSAL"]

    assert "DESERIALIZATION" in HEURISTIC_SINK_OBJECT_PREFIXES
    assert "self.serial.*" in HEURISTIC_SINK_OBJECT_PREFIXES["DESERIALIZATION"]
    assert "pcrypt.*" in HEURISTIC_SINK_OBJECT_PREFIXES["DESERIALIZATION"]
    assert "salt.payload.*" in HEURISTIC_SINK_OBJECT_PREFIXES["DESERIALIZATION"]


def test_heuristic_sink_category_resolution() -> None:
    """Verify get_sink_category resolves heuristic suffix matching and object patterns."""
    # DESERIALIZATION
    assert get_sink_category("custom_serializer.loads") == "DESERIALIZATION"
    assert get_sink_category("my_wrapper.unserialize") == "DESERIALIZATION"
    assert get_sink_category("data_loader.unpickle") == "DESERIALIZATION"
    assert get_sink_category("token_handler.decode_payload") == "DESERIALIZATION"
    assert get_sink_category("self.serial.loads") == "DESERIALIZATION"
    assert get_sink_category("self.serial.unpack") == "DESERIALIZATION"
    assert get_sink_category("self.serial.load") == "DESERIALIZATION"
    assert get_sink_category("pcrypt.decrypt") == "DESERIALIZATION"
    assert get_sink_category("pcrypt.loads") == "DESERIALIZATION"
    assert get_sink_category("salt.payload.loads") == "DESERIALIZATION"
    assert get_sink_category("salt.payload.Serial") == "DESERIALIZATION"

    # DATABASE_EXECUTION
    assert get_sink_category("custom_db.execute") == "DATABASE_EXECUTION"
    assert get_sink_category("db_conn.raw_exec") == "DATABASE_EXECUTION"
    assert get_sink_category("sql_client.raw_query") == "DATABASE_EXECUTION"
    assert get_sink_category("query_builder.as_sql") == "DATABASE_EXECUTION"

    # COMMAND_EXECUTION
    assert get_sink_category("runner.call") == "COMMAND_EXECUTION"
    assert get_sink_category("cli_tool.run_cmd") == "COMMAND_EXECUTION"
    assert get_sink_category("executor.exec_cmd") == "COMMAND_EXECUTION"
    assert get_sink_category("builder.format_cmd") == "COMMAND_EXECUTION"
    assert get_sink_category("proc.spawn") == "COMMAND_EXECUTION"

    # PATH_TRAVERSAL
    assert get_sink_category("file_path.joinpath") == "PATH_TRAVERSAL"
    assert get_sink_category("fs_handler.open_file") == "PATH_TRAVERSAL"
    assert get_sink_category("storage_service.get_file") == "PATH_TRAVERSAL"

    # Preservation of canonical ABSTRACT_SINK_CATEGORIES
    assert get_sink_category("pickle.loads") == "SERIALIZATION"
    assert get_sink_category("yaml.unsafe_load") == "SERIALIZATION"
    assert get_sink_category("open") == "FILE_IO"
    assert get_sink_category("cursor.execute") == "DATABASE_EXECUTION"
    assert get_sink_category("subprocess.run") == "COMMAND_EXECUTION"

    # Exclusion of safe calls and generic identifiers
    assert get_sink_category("json.loads") is None
    assert get_sink_category("ujson.loads") is None
    assert get_sink_category("simplejson.loads") is None
    assert get_sink_category("get") is None
    assert get_sink_category("len") is None
    assert get_sink_category("unknown_method") is None
    assert get_sink_category("custom_safe_func") is None


def test_find_sink_anchors_heuristic_matching() -> None:
    """Verify find_sink_anchors generates SinkAnchor objects for heuristic wrappers."""
    code = (
        "def process(payload, sql, cmd, path):\n"
        "    res1 = self.serial.loads(payload)\n"
        "    res2 = db.raw_query(sql)\n"
        "    res3 = runner.run_cmd(cmd)\n"
        "    res4 = p.joinpath(path)\n"
        "    res5 = pcrypt.decrypt(payload)\n"
        "    res6 = salt.payload.loads(payload)\n"
        "    res7 = query.as_sql()\n"
        "    res8 = fs.open_file(path)\n"
        "    res9 = storage.get_file(path)\n"
        "    res10 = executor.exec_cmd(cmd)\n"
        "    res11 = builder.format_cmd(cmd)\n"
        "    res12 = proc.spawn(cmd)\n"
        "    res13 = db_conn.raw_exec(sql)\n"
        "    res14 = codec.decode_payload(payload)\n"
        "    res15 = reader.unpickle(payload)\n"
        "    res16 = handler.unserialize(payload)\n"
    )

    anchors = find_sink_anchors(code)
    anchor_map = {a.line_number: a for a in anchors}

    # Line 2: self.serial.loads -> DESERIALIZATION
    assert 2 in anchor_map
    assert anchor_map[2].sink_category == "DESERIALIZATION"
    assert anchor_map[2].target_variable == "payload"

    # Line 3: db.raw_query -> DATABASE_EXECUTION
    assert 3 in anchor_map
    assert anchor_map[3].sink_category == "DATABASE_EXECUTION"
    assert anchor_map[3].target_variable == "sql"

    # Line 4: runner.run_cmd -> COMMAND_EXECUTION
    assert 4 in anchor_map
    assert anchor_map[4].sink_category == "COMMAND_EXECUTION"
    assert anchor_map[4].target_variable == "cmd"

    # Line 5: p.joinpath -> PATH_TRAVERSAL
    assert 5 in anchor_map
    assert anchor_map[5].sink_category == "PATH_TRAVERSAL"
    assert anchor_map[5].target_variable == "path"

    # Line 6: pcrypt.decrypt -> DESERIALIZATION
    assert 6 in anchor_map
    assert anchor_map[6].sink_category == "DESERIALIZATION"
    assert anchor_map[6].target_variable == "payload"

    # Line 7: salt.payload.loads -> DESERIALIZATION
    assert 7 in anchor_map
    assert anchor_map[7].sink_category == "DESERIALIZATION"
    assert anchor_map[7].target_variable == "payload"

    # Line 8: query.as_sql -> DATABASE_EXECUTION (no args -> target_variable None)
    assert 8 in anchor_map
    assert anchor_map[8].sink_category == "DATABASE_EXECUTION"
    assert anchor_map[8].target_variable is None

    # Line 9: fs.open_file -> PATH_TRAVERSAL
    assert 9 in anchor_map
    assert anchor_map[9].sink_category == "PATH_TRAVERSAL"
    assert anchor_map[9].target_variable == "path"

    # Line 10: storage.get_file -> PATH_TRAVERSAL
    assert 10 in anchor_map
    assert anchor_map[10].sink_category == "PATH_TRAVERSAL"
    assert anchor_map[10].target_variable == "path"

    # Line 11: executor.exec_cmd -> COMMAND_EXECUTION
    assert 11 in anchor_map
    assert anchor_map[11].sink_category == "COMMAND_EXECUTION"
    assert anchor_map[11].target_variable == "cmd"

    # Line 12: builder.format_cmd -> COMMAND_EXECUTION
    assert 12 in anchor_map
    assert anchor_map[12].sink_category == "COMMAND_EXECUTION"
    assert anchor_map[12].target_variable == "cmd"

    # Line 13: proc.spawn -> COMMAND_EXECUTION
    assert 13 in anchor_map
    assert anchor_map[13].sink_category == "COMMAND_EXECUTION"
    assert anchor_map[13].target_variable == "cmd"

    # Line 14: db_conn.raw_exec -> DATABASE_EXECUTION
    assert 14 in anchor_map
    assert anchor_map[14].sink_category == "DATABASE_EXECUTION"
    assert anchor_map[14].target_variable == "sql"

    # Line 15: codec.decode_payload -> DESERIALIZATION
    assert 15 in anchor_map
    assert anchor_map[15].sink_category == "DESERIALIZATION"
    assert anchor_map[15].target_variable == "payload"

    # Line 16: reader.unpickle -> DESERIALIZATION
    assert 16 in anchor_map
    assert anchor_map[16].sink_category == "DESERIALIZATION"
    assert anchor_map[16].target_variable == "payload"

    # Line 17: handler.unserialize -> DESERIALIZATION
    assert 17 in anchor_map
    assert anchor_map[17].sink_category == "DESERIALIZATION"
    assert anchor_map[17].target_variable == "payload"


def test_heuristic_backward_slicing(slicer: ASTSlicer) -> None:
    """Verify backward slicing from heuristic custom wrapper sinks."""
    code = (
        "def execute_flow(raw_input):\n"
        "    cleaned = raw_input.strip()\n"
        "    command = 'run ' + cleaned\n"
        "    runner.run_cmd(command)\n"
    )

    res = slicer.slice_from_sink(code, 4, target_var="command")
    assert res.completeness_status == COMPLETENESS_COMPLETE
    assert res.sink_category == "COMMAND_EXECUTION"
    assert res.sliced_lines == [1, 2, 3, 4]
    assert "runner.run_cmd(command)" in res.sliced_code





