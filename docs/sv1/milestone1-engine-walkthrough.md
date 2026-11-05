# Hiểu các engine qua mốc SV1 đầu tiên

## 1. Adapter khác scanner

Các adapter không quét mạng hoặc image. Chúng đọc file đã có và chuyển từ schema bên ngoài sang common.schemas. Vì vậy demo chạy được dù máy chưa cài Nmap/Trivy. Fixture chỉ mô phỏng cấu trúc đầu ra của chúng.

Nmap adapter lấy host đang up và cổng open. IP 10.10.0.10 được map qua inventory thành WEB01; port tcp/443 thành service_id WEB01:tcp/443. Adapter giữ criticality/internet_facing/sensitive_data là unknown, không đoán ngữ cảnh từ cổng. Inventory cung cấp các thuộc tính này khi merge.

Trivy adapter nhận asset_id từ config. Mỗi CVE/package trở thành finding, service_id chỉ được gán khi service_by_package khai báo. Một package có mặt trong image chưa đủ chứng minh nó là dịch vụ mạng có thể khai thác.

## 2. Vì sao phải ghép inventory?

Scanner biết quan sát kỹ thuật, người quản lý biết tầm quan trọng và dữ liệu nhạy cảm của tài sản. Hai nguồn trả lời câu hỏi khác nhau. Trong demo, inventory xác định WEB01/DB01 và ngữ cảnh; Nmap bổ sung dịch vụ/phiên bản. merge_assets giữ ưu tiên inventory cho trường có giá trị và cảnh báo scanner-only assets. Xung đột nhiều file scanner còn là hạng mục kế tiếp, không được coi đã sửa bởi demo này.

## 3. Enrichment thực hiện phép tra cứu gì?

Engine lấy vulnerability_id làm khóa tra EPSS và KEV. Không hỏi LLM, không tự tính lại CVSS và không tính điểm rủi ro tổng hợp.

Trong lần 1, alpha có EPSS 0.20 và không nằm trong KEV mẫu; lần 2 có 0.60 và được thêm vào catalog mẫu. Hai giá trị được điền vào finding mới kèm evidence, model/date và enriched_at; input finding không bị sửa. Missing EPSS phải là null, không phải 0.

`offline=true` được truyền từ pipeline → load_threat_data → fetch_cached. Nhánh này chỉ đọc file rồi parse, không thử mạng trước. Không có file thì lỗi ResourceNotFoundError; file hỏng thì parser báo ContractError. Nó không cập nhật feed cũ và luôn cảnh báo việc không kiểm bản mới trên mạng.

Các số EPSS/KEV demo chỉ là oracle synthetic. Kiến thức nền để đọc tiếp: [EPSS FAQ](https://www.first.org/epss/faq), [dữ liệu EPSS](https://www.first.org/epss/data), [mirror KEV chính thức](https://github.com/cisagov/kev-data). Nguồn được dùng trong kế hoạch nghiên cứu trước đó; dữ liệu demo không được tải từ các nguồn này.

## 4. Validation bảo đảm gì?

Models kiểm kiểu, trường/range, timezone-aware và extra fields; service kiểm ID trùng và tham chiếu. Finding WEB01 gắn dịch vụ của DB01 phải bị từ chối. Hợp lệ schema chưa đồng nghĩa có đủ topology hoặc đủ dữ liệu tính risk.

Sau khi pipeline xuất dataset.json, runner dùng load_dataset đọc lại và so bằng snapshot trong bộ nhớ. Đây là kiểm tra round trip thật, không chỉ xem file tồn tại.

## 5. History/diff không phải máy xác nhận vá

History lưu hai snapshot. diff_datasets so ID và các trường nghiệp vụ được hỗ trợ. Demo đổi EPSS/KEV, criticality, service version nên các thay đổi có oracle cụ thể. Finding beta biến mất chỉ được gọi removed, không khẳng định đã vá vì một lần scan có thể thiếu coverage.

Finding ID hiện gồm asset/CVE/package ID; chưa thay bằng identity artifact mới. Rules diff và các giới hạn khác vẫn còn trong backlog. Không sử dụng mốc này làm chứng nhận history toàn diện.

## 6. Cách biết kết quả đúng

expected.json được khai báo trước với counts, finding IDs, giá trị và các field diff mong đợi. Runner tạo observed từ output thật và yêu cầu khớp expected, sau đó lưu verification.json. Cố ý đổi expected phải làm demo thất bại. Tests cũng chặn HTTP, xác nhận không ghi đè folder cũ và chạy hai lần độc lập để so byte snapshot.

Mốc tiếp theo là làm bền input/merge và feed integrity; không cần sửa risk formula hoặc graph algorithm để hoàn thành bước này.
