# SV1-0006: Lưu snapshot bất biến trong PostgreSQL bằng migration SQL đánh số

Trạng thái: đề xuất của SV1, cần người điều phối duyệt (ARCHITECTURE.md mục 2 và 4).

## Quyết định

- Sáu bảng: `datasets`, `assets`, `services`, `findings`, `connections`, `exploit_rules`; tên số
  nhiều, cột đúng tên trường chuẩn, có khóa ngoại và ràng buộc miền.
- Migration là các file `migrations/NNNN_*.sql` chạy theo thứ tự, mỗi file một giao dịch, ghi vào
  `schema_migrations`. Chạy bằng `python -m sv1_data.db migrate`; không có chỗ nào tự tạo bảng.
- Snapshot bất biến: một `dataset_id` ứng với một `content_sha256`. Cột `row_order` giữ nguyên thứ
  tự bản ghi.
- Địa chỉ CSDL chỉ lấy từ biến môi trường `APP_DATABASE_URL`.
- Kiểm thử dùng SQLite với cùng SQL (có bật khóa ngoại) nên không cần Docker.

## Chưa làm

Đọc cấu hình tập trung qua `common/config.py`, `.env.example` và `pyproject.toml` là việc của người
điều phối và SV4. Hiện `sv1_data/db.py` đọc biến môi trường trực tiếp.
