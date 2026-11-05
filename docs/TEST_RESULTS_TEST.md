# Kết quả kiểm tra nhánh test — 05/11/2026

Chạy trên bản sao chuẩn bị push, dùng Python 3.14.6 và thư viện đã cài trong môi trường của máy SV4. Không gọi scanner hoặc model AI thật. Đây chưa phải kiểm chứng cài mới bằng uv trên máy khác.

| Kiểm tra | Kết quả |
|---|---|
| `python -B -m pytest -q` | 494 passed, 6 subtests passed |
| `python -B -m sv1_data.demo --output <thư mục mới>` | Đạt đối chiếu đáp án hai lần nhập offline |

Demo mỗi lần có 2 assets, 2 services, 3 findings; lần hai thêm 1, mất dấu 1, đổi 1 finding, đổi 1 tài sản và 1 dịch vụ. Nguồn dữ liệu là synthetic.

Chưa kiểm chứng: Python 3.11, PostgreSQL thật, Docker, scanner thật, cài đặt sạch trên máy khác và chất lượng AI qua một bộ đánh giá đầy đủ. Các tests AI mặc định dùng phản hồi giả lập để không phụ thuộc mạng/model.

Không đưa thư mục môi trường ảo, kết quả chạy tạm hoặc lịch sử cá nhân vào nhánh này.
