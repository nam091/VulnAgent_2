# experiments/codex_luna — Codex transport cho gpt-6-luna (chỉ phục vụ thực nghiệm)

Module **độc lập**, không nằm trong đường chạy chính của đồ án. Không tệp nào trong
`src/` import package này. Mục đích: chạy thực nghiệm với `gpt-6-luna` qua backend
Codex để **thu được reasoning summary + reasoning tokens**, thứ mà alias `cx/gpt-6-luna`
trên 9Router không trả về.

## Vì sao cần module riêng

| Đường | Kết quả |
|---|---|
| 9Router `cx/gpt-6-luna` (`/v1/chat/completions`) | chỉ trả `content` + `role`; không có `reasoning_content`, không có `reasoning_tokens` |
| Codex `/backend-api/codex/responses` | trả `reasoning.summary`, `response.reasoning_summary_text.delta`, `output_tokens_details.reasoning_tokens` |

Hai đường gọi **cùng một model**. `cx/` chỉ là alias của router nên module này tự
chuẩn hoá `cx/gpt-6-luna` → `gpt-6-luna`.

## Ràng buộc

- **Chỉ cho phép `gpt-6-luna`.** Truyền id khác sẽ raise `ValueError` ngay.
- Module không ghi gì vào `src/`, không sửa `auth.json` trừ khi refresh token.

## Cài đặt và chạy

```bash
# 1. Kiểm tra token còn hạn bao lâu
python -m experiments.codex_luna.run_experiment --token-status

# 2. Thử một lượt suy luận (rẻ, ~50 token)
python -m experiments.codex_luna.run_experiment --probe

# 3. Chạy pipeline thật (T2 + T3) trên một tệp
python -m experiments.codex_luna.run_experiment --scan path/to/file.py

# 4. Chỉ T2, bỏ T3
python -m experiments.codex_luna.run_experiment --scan path/to/file.py --no-verify

# 5. Đổi mức suy luận
python -m experiments.codex_luna.run_experiment --scan path/to/file.py --effort medium
```

Kết quả ghi vào `experiments/codex_luna/runs/`.

## Cách nó nối vào pipeline mà không sửa `src/`

`run_experiment.py` monkeypatch `openai.Client` **trong tiến trình của chính nó**:

```python
openai.Client = lambda **kwargs: ShimClient(reasoning_effort=effort)
```

Vì cả Tầng 2 (`AIClient._analyze_with_openai`) và Tầng 3
(`Scanner._run_verification` → `VerificationAgent`) đều lấy client qua
`analyzer.ai_client.openai_client`, một điểm patch là đủ cho cả hai.

`ShimClient` chỉ giả lập đúng một mặt API: `chat.completions.create(...)`, trả về
object có `.choices[0].message` (kèm `.reasoning_content` và `.tool_calls`) và
`.usage` (kèm `.completion_tokens_details.reasoning_tokens`).

## Chuyển đổi giao thức (chat/completions → Responses)

| OpenAI chat | Codex Responses |
|---|---|
| `role: system` | `instructions` (chuỗi riêng, không nằm trong `input`) |
| `role: user/assistant` | `{type:"message", role, content:[{type:"input_text"/"output_text", text}]}` |
| `assistant.tool_calls` | `{type:"function_call", call_id, name, arguments}` |
| `role: tool` | `{type:"function_call_output", call_id, output}` |
| `tools:[{type:"function",function:{...}}]` | `tools:[{type:"function", name, description, parameters}]` |
| `reasoning_effort` | `reasoning:{effort, summary:"auto"}` |
| (không có) | `include:["reasoning.encrypted_content"]` |
| (không có) | `text:{verbosity:"low"}` |

## Đã kiểm chứng

```
$ python -m experiments.codex_luna.run_experiment --probe
reasoning echo   : {"effort": "high", "summary": "detailed", "context": "all_turns", "mode": "standard"}
reasoning summary: **Calculating 17×20−17**
answer           : 323
tokens           : in=23 out=25 reasoning=18 total=48
```

```
$ python -m experiments.codex_luna.run_experiment --scan .../BenchmarkTest00078.py
findings      : 1
  CRITICAL  CWE-502  INSECURE_DESERIALIZATION  BenchmarkTest00078.py:53 [CONFIRMED] verdict=confirmed thinking=66c
thinking tok  : 424
tokens        : in=20246 out=1239
```

Debug traces ghi được cả hai tầng:

| Trace | Thinking | Nội dung |
|---|---|---|
| `llm_scan` | 80 ký tự | `**Preparing cookie deserialization finding****Refining deserialization finding**` |
| `verification` | 66 ký tự | `**Inspecting cookie deserialization****Mapping cookie taint path**` |

## Giới hạn phải nêu trong luận văn

1. **Chỉ có summary, không có full chain-of-thought.** `reasoning.encrypted_content`
   khoảng 1.500 ký tự là dữ liệu mã hoá, không giải mã được. Trường `thinking` của
   hệ thống chỉ là **reasoning summary** do server sinh.
2. **Bắt buộc streaming.** Summary chỉ tồn tại dưới dạng delta event; chế độ
   non-streaming sẽ không thu được gì.
3. **Đây là endpoint nội bộ của ChatGPT**, không phải API công khai. Không cam kết
   ổn định, có thể đổi schema hoặc chặn bất kỳ lúc nào.
4. **Token sống ngắn.** Trường `expires` trong `auth.json` hiện còn vài ngày.
   `auth.py` có luồng refresh nhưng **chỉ chạy được khi credential có `clientId`**;
   nếu thiếu, module báo lỗi rõ ràng và yêu cầu đăng nhập lại thay vì đoán.
5. **Không dùng cho benchmark chính thức** nếu chưa ghi rõ transport. Kết quả qua
   Codex và qua 9Router có thể khác nhau về phân phối token, không chỉ về reasoning.

## Cấu trúc

```
experiments/codex_luna/
├── __init__.py          # export công khai
├── auth.py              # đọc/refresh credential, không bao giờ log token
├── client.py            # CodexClient: streaming SSE → text + reasoning + tool_calls + usage
├── openai_shim.py       # ShimClient: giả lập openai.Client.chat.completions
├── run_experiment.py    # CLI: --probe / --scan / --token-status
└── runs/                # kết quả JSON từng lần chạy
```
