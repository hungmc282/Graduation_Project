# Graduation Project

Hệ thống ưu tiên xử lý lỗ hổng dựa trên ngữ cảnh tài sản, đường tấn công và lan truyền rủi ro.

## Phân công và nhánh

| Người | Nhánh | Thư mục |
|---|---|---|
| SV1 — Dữ liệu | `sv1-data` | [sv1_data](sv1_data/) |
| SV2 — Attack Graph | `sv2-attack-graph` | [sv2_attack_graph](sv2_attack_graph/) |
| SV3 — Risk và ưu tiên | `sv3-risk` | [sv3_risk](sv3_risk/) |
| SV4 — Ứng dụng và LLM | `sv4-app-llm` | [sv4_app_llm](sv4_app_llm/) |

`main` là bản tích hợp ổn định. Bốn nhánh phụ trách được giữ lâu dài; nhóm tự tạo nhánh con khi cần. Chưa có mã ứng dụng hay thư viện bắt buộc trong bộ khung này.

Luồng: SV1 cung cấp dữ liệu → SV2 dựng graph → SV3 tính rủi ro/ưu tiên → SV4 hiển thị và dùng LLM giải thích.

LLM chỉ hỗ trợ trích xuất thuộc tính, giải thích và sinh báo cáo; Risk Engine tính điểm minh bạch, có thể tái lập.

Đọc [quy tắc làm việc nhóm](CONTRIBUTING.md) trước khi bắt đầu.


## Bản làm việc duy nhất và lệnh chạy

Thư mục sử dụng: `/Users/hungmc/Graduation_Project/Graduation_Project`.
Code SV1/SV2/SV3 giữ trong thư mục riêng; SV4 gọi các facade, không chép engine vào giao diện.

```bash
cd /Users/hungmc/Graduation_Project/Graduation_Project
source sv4_app_llm/.venv/bin/activate
uv sync --active --locked
# Dashboard chính: tài sản, phân tích, mô phỏng vá, báo cáo và AI
python -m streamlit run sv4_app_llm/app.py
# Màn hình mô phỏng độc lập cũ (tùy chọn)
python -m streamlit run sv4_app_llm/apps/risk_analysis/app.py
# Kiểm thử toàn dự án
python -B -m pytest -q
# Demo nhập dữ liệu SV1 offline
python -m sv1_data.demo
```

Hướng dẫn chi tiết: [SV4](sv4_app_llm/README.md), [SV1](sv1_data/USAGE.md).
Ứng dụng mô phỏng xử lý dữ liệu thật bằng code nhưng các kịch bản mẫu vẫn là giả lập.
Các bản sao lưu trước khi hợp nhất nằm trong `local_data/consolidation-backup/` và được Git bỏ qua.
