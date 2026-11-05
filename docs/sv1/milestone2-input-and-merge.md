# SV1 mốc 2 — Kiểm tra đầu vào và ghép dữ liệu

## Chính sách đã hiện thực

Giữ nguyên ID finding và schema canonical. Không chọn quan sát “mới nhất” hoặc file đầu khi cùng ID có dữ liệu khác nhau. Dữ liệu synthetic và cơ chế offline của mốc 1 giữ nguyên.

1. Các model scanner có cùng ID và toàn bộ nội dung bằng nhau: giữ một bản, tăng bộ đếm duplicate.
2. Cùng ID nhưng khác bất kỳ trường canonical nào: ContractError, kèm record_id, trường khác nhau và nguồn quan sát. Kể cả khác observed_at/evidence cũng cần người dùng chọn nguồn phù hợp. Không bỏ timestamp để làm hai quan sát khác nhau thành giống nhau.
3. Trivy cùng ID ở artifact/target khác nhau: báo lỗi, yêu cầu tách nguồn; chưa tạo ID mới hoặc thay tham chiếu SV2. So sánh context riêng vì schema Finding hiện không chứa artifact/target. Target trùng ID ngay trong một report cũng bị chặn nếu khác nhau.
4. Inventory so với scanner vẫn áp dụng precedence đã có trong merge_assets; chính sách fail-on-conflict mới áp dụng giữa các quan sát scanner cùng loại.
5. Assets/services/findings được sắp theo ID khi xuất pipeline. Với các bản ghi không mâu thuẫn, đổi thứ tự các file scanner không đổi snapshot khi thời gian chạy cố định. Report vẫn phản ánh thứ tự input và thời gian xử lý thực tế.

Model equality được dùng sau normalize, không phải so file raw từng byte. Khác biệt không được biểu diễn trong schema có thể không tham gia so sánh; đây không phải cơ chế lưu giữ mọi chi tiết scanner. Chưa giải quyết identity artifact tổng quát.

## Đầu vào được kiểm tra thêm

- Trivy Results phải là mảng/null; mỗi result phải là object.
- Vulnerabilities/Secrets phải là mảng/null; mỗi vulnerability phải là object.
- Các trường nhận diện VulnerabilityID/PkgName/PkgID/InstalledVersion, Target, ArtifactName và CreatedAt phải là chuỗi khi có giá trị.
- Port Nmap của dịch vụ TCP/UDP open phải là số nguyên ASCII 1–65535. Port hợp lệ được chuẩn hóa trước tạo service_id.
- Lỗi adapter đọc từ file được gắn đường dẫn file trong message/details; pipeline CLI hiển thị lỗi và trả exit code 1.

Giữ chính sách trước: Results/vulnerabilities không có hoặc null là rỗng; thiếu VulnerabilityID được bỏ qua và thống kê; thiếu CVSS v3 giữ null; giao thức Nmap không hỗ trợ được bỏ qua có warning. Không thay mọi trường thiếu bằng lỗi khi hợp đồng cho phép unknown.

## Đọc thống kê

report.json có thêm merge_stats:

| Trường | Ý nghĩa |
|---|---|
| duplicate_assets | Asset model giống hệt lặp giữa file Nmap |
| duplicate_services | Service model giống hệt lặp giữa file Nmap |
| duplicate_findings | Finding model giống hệt lặp giữa file Trivy |
| duplicates_within_nmap | Tổng asset/service lặp giống hệt bên trong các XML |

Trivy duplicates trong một file vẫn ở trivy_stats.duplicates_removed. Không cộng hai chỉ số này rồi gọi là số finding duy nhất; chúng đếm các bước loại trùng khác nhau. Conflicts làm pipeline dừng trước enrichment và ghi output, không có report thành công giả. Nếu thư mục đã chứa kết quả cũ, lỗi không xóa kết quả cũ; cần kiểm exit code và report của lần chạy phù hợp.

## Ví dụ tự chạy

Các file dưới data/samples/sv1_input_checks đều là synthetic, không cần mạng.

```bash
# Thành công: 2 assets và 2 services; duplicate_assets=2, duplicate_services=2
uv run python -m sv1_data.pipeline data/samples/sv1_input_checks/duplicates.json

# Thất bại có chủ đích: product_version mâu thuẫn, hiển thị hai file
uv run python -m sv1_data.pipeline data/samples/sv1_input_checks/conflict.json

# Thất bại có chủ đích: portid=abc, báo ports.port.portid và tên file
uv run python -m sv1_data.pipeline data/samples/sv1_input_checks/invalid-port.json

# Thất bại có chủ đích: Results[0] là số, phải là object
uv run python -m sv1_data.pipeline data/samples/sv1_input_checks/invalid-trivy.json
```

Cách xử lý: sửa dữ liệu scanner/config, hoặc chọn bộ quan sát thuộc cùng lần scan có căn cứ. Không xóa ngẫu nhiên bản ghi để ép chạy; lưu nguồn gốc bản bị loại và lý do chọn nếu cần nhập lại.

## Kiểm chứng và phạm vi còn lại

Regression tests: tests/sv1_data/test_sv1_input_merge.py. Bao phủ malformed structures, port sai, duplicate giống nhau, conflict cả hai thứ tự, hoán đổi input không mâu thuẫn, Trivy khác score/artifact/target và CLI không traceback cho các lỗi được hỗ trợ.

Bộ demo `python -m sv1_data.demo` vẫn phải đạt. Mốc này chưa xử lý online feed/cache integrity, diff exploit rules, transaction output/history, mọi lỗi I/O hệ thống hoặc xác minh nội dung CVE. Không tuyên bố parser an toàn cho file XML bất kỳ không tin cậy.
