# VulnAgent 🛡️

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[English](README.en.md) | [Tiếng Việt](README.md)

> **VulnAgent** phát hiện các lỗ hổng bảo mật trong mã nguồn bằng cách vận hành một công cụ
> quét theo quy tắc (Rule engine - Semgrep) và một mô hình ngôn ngữ lớn (LLM) dưới dạng **hai tầng độc lập**,
> sau đó hợp nhất kết quả. Các phát hiện được cả hai tầng đồng thuận được gắn nhãn `corroborated` (`both-engines`);
> các phát hiện chỉ từ một tầng được đánh dấu là đơn nguồn (`rule-only` hoặc `llm-only`).
> Khâu xác minh cụ thể được tách biệt khỏi khâu phát hiện ban đầu và đòi hỏi bằng chứng mã nguồn có thể kiểm chứng.

## Tại sao cần hai tầng độc lập

Được đánh giá trên tập kiểm thử hiệu chỉnh ban đầu (11 lỗ hổng được gán nhãn trên ba file, kèm các hàm đối chứng sạch có ghi chép):

| Cấu hình kiểm thử | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| VulnAgent, tất cả phát hiện | 11 | 9 | 0 | 0.550 | **1.000** | 0.710 |
| **VulnAgent, chỉ phát hiện đồng thuận** | 8 | **0** | 3 | **1.000** | 0.727 | **0.842** |
| Semgrep thuần túy | 8 | 2 | 3 | 0.800 | 0.727 | 0.762 |
| LLM thuần túy | 11 | 7 | 0 | 0.611 | **1.000** | 0.759 |
| Bandit (baseline) | 7 | 6 | 4 | 0.538 | 0.636 | 0.583 |

Hãy đọc kỹ hàng đầu tiên: **việc đơn thuần hợp nhất (union) cả hai tầng còn cho kết quả tệ hơn
từng tầng chạy riêng lẻ.** Nó kế thừa toàn bộ dương tính giả (cảnh báo sai) từ cả hai bên và chỉ đạt
F1 0.710, thấp hơn mức 0.762 của Semgrep và 0.759 của LLM. Chạy hai engine rồi lấy hợp kết quả không mang lại giá trị nào.

Điều tạo nên giá trị nằm ở hàng thứ hai. Vì hai tầng hoạt động **độc lập**,
sự đồng thuận theo phương pháp phỏng đoán giữa chúng đóng vai trò như một bộ lọc trên các phát hiện ứng viên.
Lọc theo các phát hiện được cả hai engine xác nhận giúp giảm nhiễu đáng kể trên mẫu dữ liệu này.

Vì vậy, giá trị không nằm ở chỗ "hai engine tìm được nhiều hơn". Giá trị nằm ở việc **sự đồng thuận
độc lập cung cấp một tín hiệu xếp hạng heuristic**, đó là lý do tầng quy tắc
không được dùng làm bộ lọc trước cho tầng LLM: việc chặn tầng này bằng tầng kia sẽ
phá hủy tính độc lập mà toàn bộ thiết kế dựa vào, đồng thời sẽ loại bỏ
các thông tin đăng nhập cố định (hardcoded credentials) mà tầng quy tắc chưa từng có mẫu nhận diện.

Hai hàng này cũng phân định một sự đánh đổi thực tế mà bạn lựa chọn tùy theo ngữ cảnh: báo cáo
tất cả cho con người xem xét khi review Pull Request, hoặc chặn dựa trên
các phát hiện đồng thuận để giảm tối đa nhiễu. Cờ `--confirmed-only` (bí danh của corroborated)
cho phép chuyển đổi giữa hai chế độ này.

> **Về kích thước tập dữ liệu.** Mười một nhãn trên ba file là một bài kiểm thử smoke test, không phải
> một bài đánh giá toàn diện. Các con số có thể biến động đáng kể theo từng mẫu ở quy mô này. Hãy coi
> hình thái kết quả này mang tính tạm thời cho đến khi tập dữ liệu đạt khoảng 50–100 nhãn.

VulnAgent cũng thực hiện được ba việc mà một công cụ theo quy tắc về mặt cấu trúc không thể làm được:

- **Liên kết các phát hiện thành chuỗi tấn công (attack paths)** kèm xác suất và điều kiện tiên quyết
- **Viết các bản vá nhận biết ngữ cảnh**, được kiểm chứng tính hợp lệ trước khi áp dụng
- **Phát hiện các khiếm khuyết mức logic nghiệp vụ** mà không thể rút gọn thành một mẫu cú pháp cố định

## Cài đặt

```bash
git clone https://github.com/nam091/VulnAgent_2.git
cd VulnAgent_2
python -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
cp .env.example .env      # sau đó thêm API key của bạn
```

## Cách sử dụng

### Dòng lệnh (CLI)

```bash
vulnagent scan .                          # quét toàn bộ thư mục
vulnagent scan app.py --verbose           # quét một file, hiển thị tác động và cách sửa
vulnagent scan . --no-llm                 # chỉ chạy tầng quy tắc, khởi động ~10s
vulnagent scan . --format sarif -o out.sarif
vulnagent fix . --verify                  # áp dụng bản vá, tự hoàn tác nếu kết quả tệ hơn
vulnagent baseline .                      # đóng băng các phát hiện hiện tại làm nợ kỹ thuật
```

Mã thoát (Exit codes): `0` sạch, `1` phát hiện vượt ngưỡng chặn, `2` lỗi hệ thống.

Các cờ hữu ích:

| Cờ | Tác dụng |
|---|---|
| `--fail-on {critical,high,medium,low,info,never}` | Ngưỡng nghiêm trọng để chặn build (mặc định `high`) |
| `--confirmed-only` | Chỉ các phát hiện đồng thuận mới làm fail build |
| `--baseline [FILE] --fail-on-new` | Chỉ các phát hiện mới phát sinh mới làm fail build |
| `--min-risk N` | Điểm rủi ro tối thiểu để file được chuyển lên tầng LLM |
| `--max-llm-files N` | Giới hạn cứng số lượng file gửi tới LLM, ưu tiên rủi ro cao trước |
| `-j N` | Số luồng gọi LLM đồng thời (mặc định 5) |

### Máy chủ MCP — Dành cho các AI coding agent

Cho phép Claude Code, Cursor hoặc bất kỳ MCP client nào quét đoạn mã nó vừa viết,
**trước khi** bàn giao cho người dùng.

```json
{
  "mcpServers": {
    "vulnagent": {
      "command": "python",
      "args": ["/absolute/path/to/VulnAgent_2/src/mcp_server.py"]
    }
  }
}
```

Công cụ: `scan_code`, `scan_file`, `scan_directory`, `capabilities`. Sử dụng
`mode="fast"` bên trong vòng lặp sinh mã (chỉ chạy tầng quy tắc, mất khoảng vài giây -
chủ yếu là thời gian khởi động engine cố định, kích thước đoạn mã hầu như không ảnh hưởng) và
`mode="deep"` cho lần xem xét cuối cùng.

### Giao diện Web (Web UI)

```bash
vulnagent serve      # http://localhost:8000
```

Dán mã nguồn, tải lên một file, hoặc trỏ tới một repository công khai. Tài liệu API tại
`/docs`.

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: nam091/VulnAgent_2@main
    with:
      path: src
      fail-on: high
      confirmed-only: 'true'
      openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

Kết quả sẽ xuất hiện trong tab **Security** của repository và dưới dạng chú thích inline trên PR, thông qua chuẩn SARIF.

## Bỏ qua các phát hiện (Suppression)

```python
cursor.execute(query)  # vulnagent: ignore[SQL_INJECTION] query is a literal constant
```

Comment `# vulnagent: ignore` dạng trần sẽ bỏ qua mọi loại lỗi trên dòng đó; `# vulnagent: ignore-file` bỏ qua toàn bộ file. Các comment nhận diện có sẵn như `# nosec` và `# nosemgrep` cũng được công nhận tương đương.

Đối với một codebase có sẵn, hãy ưu tiên dùng mốc cơ sở (baseline) thay vì bỏ qua hàng loạt:

```bash
vulnagent baseline .                                  # ghi lại các phát hiện hiện tại
vulnagent scan . --baseline --fail-on-new             # chỉ các lỗi mới phát sinh mới làm fail
```

## Cấu hình

```ini
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.xiaomimimo.com/v1   # tùy chọn, bất kỳ nhà cung cấp tương thích nào
OPENAI_MODEL=mimo-v2.5-pro                      # tùy chọn
ANTHROPIC_API_KEY=sk-ant-...                    # tùy chọn dự phòng
```

## Chi phí và tốc độ

Một lượt quét LLM toàn diện qua từng file trong repository vừa tốn kém vừa
chậm chạp, do đó ba cơ chế sau được áp dụng để ràng buộc:

- **Khám phá (Discovery)** bỏ qua `venv/`, `node_modules/`, thư mục build và bất kỳ thứ gì
  được khai báo trong `.gitignore`. Trên repository này, phạm vi quét thu gọn còn 10 file thay vì 3,974 file.
- **Định tuyến theo rủi ro (Risk routing)** chỉ gửi các file có nội dung gợi ý điều gì đó
  đáng để phân tích ngữ nghĩa — input người dùng, SQL, subprocess, auth, crypto — tới
  LLM. Tầng quy tắc vẫn bao phủ tất cả mọi file.
- **Bộ nhớ đệm theo hash nội dung (Content-hash caching)** đảm bảo một file không đổi nội dung sẽ không bao giờ bị trả phí lần hai.
  Một lượt quét lặp lại trên ví dụ mẫu giảm thời gian từ 51s xuống còn 11s.

## Đo lường & Đánh giá (Evaluation)

```bash
python eval/run_eval.py
```

Đo điểm mô hình lai so với Semgrep thuần túy, LLM thuần túy và Bandit trên tập dữ liệu
được gán nhãn thủ công. Xem [eval/README.md](eval/README.md) để biết cách thêm các mẫu dữ liệu mới.

## Giới hạn kỹ thuật

Được tuyên bố rõ ràng, bởi vì một công cụ quét phóng đại độ bao phủ của nó còn tệ hơn
một công cụ dám thừa nhận giới hạn của mình:

- **Chỉ hỗ trợ Python.** Các ngôn ngữ khác hiện chưa được hỗ trợ.
- **Phân tích theo từng file.** Dữ liệu nhiễm (taint) đi qua ranh giới module khác chưa được
  theo vết; phân tích đa file xuyên module là một tính năng tính phí của Semgrep.
- **Tầng quy tắc cần một nguồn nhiễm (taint source) được nhận diện.** Nó suy luận từ các
  điểm vào framework như `request.args`. Một hàm độc lập không có điểm vào nào như vậy, do đó
  `os.system("echo " + cmd)` bên trong một hàm thuần `def run(cmd)` sẽ được báo sạch
  bởi `--no-llm` và báo CRITICAL khi bật tầng LLM. Một lượt quét chỉ dùng quy tắc trên
  mã không dùng framework chứng minh được rất ít điều.
- **Các phát hiện chỉ từ LLM (LLM-only) không thể tái lập hoàn toàn giữa các lượt chạy.** Ngay cả ở nhiệt độ
  bằng 0, các phát hiện ở vùng biên với độ tin cậy thấp vẫn dao động. Các phát hiện đồng thuận (Confirmed) thì
  ổn định. Đây là lý do tại sao `--confirmed-only` là cổng chặn CI được khuyến nghị.
- **Các bản vá được tạo ra cần con người kiểm duyệt.** Bản vá được kiểm tra cú pháp và phân loại,
  và chỉ những thay thế sạch mới được áp dụng tự động — tuy nhiên một bản vá có thể parse cú pháp
  chính xác nhưng vẫn làm thay đổi hành vi nghiệp vụ, do đó cờ `--verify` sẽ quét lại và tự động hoàn tác
  nếu thay đổi làm tình hình tệ hơn.
- **Một lượt quét sạch không phải là bằng chứng của sự an toàn tuyệt đối.** Nó chỉ có nghĩa là các engine này không
  tìm thấy gì, và đó là một khẳng định yếu hơn rất nhiều.
