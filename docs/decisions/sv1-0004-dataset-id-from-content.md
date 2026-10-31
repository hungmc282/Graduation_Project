# SV1-0004: `dataset_id` sinh từ mã băm nội dung

Trạng thái: đã áp dụng (theo ARCHITECTURE.md mục 6.4: đổi dữ liệu phải đổi `dataset_id`).

## Quyết định

`dataset_id` = tên gốc + `-` + 12 ký tự đầu của SHA-256 nội dung, ví dụ `dvwa-lab-v1-58f1463aaa0a`.
Mã băm bỏ qua `dataset_id`, `created_at` và `enriched_at` của từng finding (ba giá trị đổi mỗi lần
chạy nhưng không phải dữ liệu mới). Chạy lại cùng dữ liệu cho cùng ID; finding mới, điểm KEV hoặc
EPSS khác, thuộc tính tài sản khác thì cho ID mới.

## Hệ quả

Kho lưu trong CSDL dùng cùng mã băm để từ chối việc dùng một ID cho nội dung khác. Dữ liệu EPSS đổi
hằng ngày nên có thể sinh ID mới mỗi ngày: đó là đúng với quy tắc vì nội dung thật sự đã đổi.
