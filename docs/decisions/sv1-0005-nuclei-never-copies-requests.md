# SV1-0005: Không bao giờ sao chép request, response và cookie của Nuclei

Trạng thái: đã áp dụng.

## Bối cảnh

Mỗi phát hiện của Nuclei chứa nguyên văn `request`, `response`, `curl-command` và
`extracted-results`. Các trường này có thể chứa cookie, phiên làm việc hay mật khẩu. Hợp đồng yêu
cầu `evidence` đã lọc dữ liệu nhạy cảm.

## Quyết định

Adapter chỉ ghi vào `evidence`: tên template, tên phát hiện, mức nghiêm trọng của Nuclei, địa chỉ
khớp đã cắt bỏ phần sau `?` và `#`, tên matcher, CWE, vector CVSS và một đường dẫn tham khảo
(mỗi dòng cắt tối đa 200 ký tự). Có test dùng chuỗi mồi để bảo đảm không rò rỉ. File quét thô
không được commit.
