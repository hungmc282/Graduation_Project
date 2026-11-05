# Hợp nhất về dự án người dùng — 01/11/2026

Đích: /Users/hungmc/Graduation_Project/Graduation_Project.
Giữ ứng dụng SV4 doanh nghiệp, cấu hình DB và dữ liệu người dùng.
Chuyển SV1 mới (nhánh sv1-database tới 3e0308dc), bổ sung offline/kiểm tra xung đột,
common schema, SV2, SV3, dữ liệu mẫu, migration và tests từ bản làm việc đính kèm.
Giữ ứng dụng mô phỏng tại sv4_app_llm/apps/risk_analysis, có service riêng để không
thay chữ ký service.run_analysis của ứng dụng doanh nghiệp.
Không thay .git của đích, không push GitHub. Lịch sử Git của bản đính kèm và code cũ
được lưu nén trong local_data/consolidation-backup trước khi dọn bản trùng.
Thư viện dùng chung ở pyproject.toml/uv.lock gốc; tái sử dụng sv4_app_llm/.venv.
Tài liệu gốc sources/ của ChatGPT project giữ nguyên, chỉ đọc.

## Xác minh sau hợp nhất

- 465 tests và 6 subtests đạt trong môi trường SV4 tại đích.
- Kiểm tra sáu trang doanh nghiệp và mô phỏng chain trước/sau vá F01: đạt.
- Demo SV1 offline hai lần: đạt.
- SHA-256 SQLite người dùng giữ nguyên so với bản sao lưu.
- Đã xóa bản dự án đính kèm bị dùng nhầm và bản kiểm kê cũ, giải phóng khoảng 395,7 MiB.
- Giữ nguyên 4 tài liệu nguồn trong sources/ của ChatGPT project.
- Không push GitHub; các thay đổi hợp nhất vẫn nằm trong working tree của dự án đích.
