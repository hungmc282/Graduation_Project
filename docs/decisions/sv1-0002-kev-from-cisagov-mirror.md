# SV1-0002: Tải danh mục KEV từ bản sao của CISA trên GitHub

Trạng thái: đã áp dụng.

## Bối cảnh

Trang `cisa.gov` trả HTTP 403 (từ lớp CDN) khi tải `known_exploited_vulnerabilities.json` từ mạng
của SV1, kể cả khi đổi User-Agent. Chặn này không liên quan tới cách chương trình tải.

## Quyết định

Địa chỉ mặc định là bản sao do CISA duy trì tại `github.com/cisagov/kev-data` (cùng nội dung, giấy
phép CC0). Địa chỉ gốc vẫn có trong mã (`KEV_CISA_URL`). Có thể đặt tay file vào thư mục cache.

## Hệ quả

`catalogVersion` luôn được ghi trong `evidence` nên truy được nguồn. Báo cáo thực nghiệm phải nói
rõ dữ liệu KEV lấy từ bản sao GitHub chứ không trực tiếp từ `cisa.gov`.
