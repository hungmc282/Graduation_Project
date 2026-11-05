# Tích hợp SV1–SV4 với SV2 1.0.0

Đã cập nhật local từ origin/main 756b2f4, origin/sv1-data 9bbecfb,
origin/sv2-attack-graph 8e4660e và origin/sv3-risk 9fd8168.

GraphConfig, AttackPath, GraphResult được chuyển nguyên nghĩa từ SV2 sang
common.schemas; graph_models giữ re-export cho các consumer hiện có.
Bổ sung RiskConfig, PriorityItem, AnalysisResult theo ARCHITECTURE.md,
để SV3 và SV2 dùng cùng class tại biên facade.

Kịch bản SV3 chuyển graph model reference-lab-v1 sang 1.0.0 và trạng thái
đầu vào external sang initial theo code SV2. Giữ nguyên phần còn lại của
rules và các oracle tính tay; kiểm tra lại toàn bộ trên graph engine thật.
Baseline blocked-paths-v1 nhận thêm SV2 1.0.0; demo-graph-v1 được giữ cho
kiểm tra hồi quy dùng mock, không được coi là graph engine thật.

Dependency được quản lý tại pyproject.toml và uv.lock. Python hỗ trợ
3.11–3.14; lần tích hợp này kiểm tra bằng Python 3.14 trên máy hiện tại,
chưa chứng nhận môi trường Python 3.11. Không thay thuật toán risk/graph.

UI gọi service điều phối; không tính risk trong giao diện. Demo cũ và AI
được giữ ở `sv4_app_llm/demos/saved_reports/app.py` (trước đây là
`saved_demo_app.py`). Tại thời điểm tích hợp này chưa có API, PostgreSQL, hoặc AI cho kết quả
live; không gọi scanner hay enrichment qua mạng khi chạy UI.
