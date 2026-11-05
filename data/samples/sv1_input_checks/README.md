# Bộ mẫu kiểm tra đầu vào SV1

Toàn bộ là synthetic. Xem [hướng dẫn chính sách, lệnh chạy và cách sửa lỗi](../../../docs/sv1/milestone2-input-and-merge.md).

- duplicates.json: thành công, gộp hai bản XML giống hệt và thống kê.
- conflict.json: lỗi có chủ đích do phiên bản dịch vụ mâu thuẫn.
- invalid-port.json: lỗi có chủ đích do cổng abc.
- invalid-trivy.json: lỗi có chủ đích do Results chứa số.

Các lệnh pipeline ghi kết quả thành công vào outputs/sv1-input-checks; các cấu hình này tắt enrichment nên không dùng mạng.
