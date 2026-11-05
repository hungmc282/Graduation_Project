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
