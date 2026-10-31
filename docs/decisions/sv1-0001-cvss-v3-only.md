# SV1-0001: Chỉ dùng điểm CVSS v3, không dùng v2

Trạng thái: đề xuất của SV1, cần SV3 xác nhận.

## Bối cảnh

Báo cáo Trivy chứa điểm CVSS của nhiều nguồn (NVD, Red Hat, Bitnami...), mỗi nguồn có điểm v2
và v3. Hợp đồng dữ liệu chỉ có một trường `cvss_score` và cấm so sánh ngầm các thang khác nhau.

## Quyết định

- Ưu tiên điểm v3 của NVD; nếu NVD không có thì lấy điểm v3 của nguồn khác theo thứ tự chữ cái.
- Không bao giờ dùng điểm v2. Không có thì `cvss_score` là `null`, không bịa 0.
- Nguồn điểm được ghi vào `evidence` (ví dụ `cvss source: nvd v3`) để không mất thông tin.
- Nuclei: chỉ lấy `cvss-score` khi template cung cấp; chỉ có vector thì để `null` và ghi vector
  vào `evidence`. Không tự tính điểm từ vector.

## Số liệu trên dữ liệu thật (image DVWA, 1575 finding của Trivy)

1542 finding dùng điểm NVD v3, 21 dùng điểm v3 của Bitnami, 12 là `null` (mã Debian DLA/DSA, không
phải CVE). Toàn bộ 13 finding của Nuclei là `null`.

## Hệ quả

SV3 phải xử lý `cvss_score = null` tường minh. Nếu muốn thêm điểm v2 hay phân biệt phiên bản,
cần thêm trường có kiểm soát qua PR (xem ARCHITECTURE.md mục 6.2).
