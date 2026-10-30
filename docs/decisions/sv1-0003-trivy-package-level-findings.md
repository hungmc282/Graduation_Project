# SV1-0003: Finding của Trivy ở cấp gói, gắn dịch vụ chỉ khi người dùng khai báo

Trạng thái: đề xuất của SV1, cần SV2 xác nhận.

## Bối cảnh

Trivy quét image nên lỗ hổng thuộc về gói phần mềm (ví dụ `apache2`), không thuộc về một cổng mạng.
Đồ thị tấn công của SV2 nghĩ theo dịch vụ đang mở cổng. Trên image DVWA, 1575 finding nhưng chỉ
một phần thuộc dịch vụ Apache cổng 8080.

## Quyết định

- `service_id` của finding mặc định là `null`.
- Người dùng khai báo bảng `service_by_package` (tên gói sang `service_id`) trong cấu hình.
  Adapter không bao giờ đoán quan hệ gói với dịch vụ.
- Các finding của Trivy không được gộp lại: một CVE xuất hiện ở nhiều gói (như `apache2`,
  `apache2-bin`) thì là nhiều finding.

## Hệ quả

SV2 cần quyết định finding có `service_id = null` có tham gia đồ thị hay không. Mỗi CVE bị đếm nhiều
lần ở mức finding: SV3 cần quyết định xếp hạng theo finding hay gộp theo (tài sản, CVE).
