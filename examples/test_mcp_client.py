"""
Script kiểm thử độc lập cho VulnAgent MCP Server.
Chạy trực tiếp: python examples/test_mcp_client.py
"""
import asyncio
import json
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
SERVER_SCRIPT = str(ROOT / "src" / "mcp_server.py")


async def main():
    print("[+] Khởi động và kết nối tới VulnAgent MCP Server...")
    params = StdioServerParameters(command=sys.executable, args=[SERVER_SCRIPT])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[+] Bắt tay giao thức MCP: THÀNH CÔNG!")

            # 1. Liệt kê danh mục công cụ
            tools_resp = await session.list_tools()
            tools = tools_resp.tools
            print(f"[+] Danh sách công cụ sẵn sàng ({len(tools)} tools):")
            for t in tools:
                print(f"    - {t.name}")

            # 2. Quét thử đoạn mã Python chứa Command Injection
            test_snippet = '''
import subprocess

def backup_data(user_folder):
    # Lỗ hổng Command Injection (CWE-78)
    subprocess.call(f"tar -czf backup.tar.gz {user_folder}", shell=True)
'''
            print("\n[+] Đang gọi tool scan_code (chế độ fast/offline)...")
            res = await session.call_tool("scan_code", arguments={"code": test_snippet, "mode": "fast"})
            data = json.loads(res.content[0].text)
            print(f"[+] Kết quả quét: {data.get('summary')}")
            for f in data.get("findings", []):
                print(f"    -> [{f['severity']}] {f['type']} (CWE: {f['cwe']}) tại dòng {f['start_line']}")
                print(f"       Code: {f.get('snippet')}")
                if f.get("fix"):
                    print(f"       Đề xuất sửa: {f['fix'].get('replacement')}")


if __name__ == "__main__":
    asyncio.run(main())
