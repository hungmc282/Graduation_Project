# SV1 — Mốc 1: hai lần nhập dữ liệu offline

Toàn bộ XML, JSON, CSV và số liệu ở đây được tự tạo để kiểm thử. Các ID CVE-2099-* chỉ là khóa giả lập theo định dạng CVE, không phải khẳng định có lỗ hổng thật. EPSS/KEV mẫu không phải dữ liệu FIRST/CISA đã công bố. Mốc này không chứng minh khả năng khai thác và không tự chạy scanner.

## Chạy nhanh

Từ thư mục gốc `Graduation_Project`:

```bash
uv sync --locked
uv run python -m sv1_data.demo
```

Lần đầu cần có dependency đã cài (bước uv sync có thể cần Internet). Sau đó luồng xử lý dữ liệu không gọi mạng. Có thể dùng Python trực tiếp trong môi trường đã chuẩn bị:

```bash
.venv/bin/python -m sv1_data.demo
```

Mỗi lần chạy tạo thư mục riêng dưới `outputs/sv1-milestone1/demo-*` và in đường dẫn kết quả. Không ghi đè kết quả cũ. Muốn chỉ định nơi lưu:

```bash
uv run python -m sv1_data.demo --output outputs/my-first-sv1-demo
```

Thư mục phải mới hoặc rỗng. Không cần chạy Streamlit, Ollama hoặc có scanner trên máy.

## Mốc này kiểm chứng điều gì?

```text
inventory.csv ──→ asset + ánh xạ IP
nmap.xml ───────→ asset/service ──→ ghép theo inventory
trivy.json ────→ findings + ánh xạ package/service
feeds local ───→ bổ sung EPSS/KEV (offline=true)
                         ↓
              validate → dataset.json + report.json
                         ↓
                  nạp lại và lưu history
                         ↓
             lần 2 → diff → so expected.json
```

Runner gọi pipeline thật hai lần, đọc lại dataset.json bằng loader thật, đọc lại hai snapshot từ ScanHistory và đối chiếu expected.json độc lập. Không thay engine bằng mock. Đồng hồ được cố định để snapshot có thể tái lập; thời gian xử lý trong report không yêu cầu trùng từng byte.

## Đầu vào từng lần

- `inventory.csv`: WEB01 ↔ 10.10.0.10 và DB01 ↔ 10.10.0.20, có ngữ cảnh rủi ro.
- `nmap.xml`: hai dịch vụ WEB01:tcp/443 và DB01:tcp/5432.
- `trivy.json`: ba occurrences package/CVE trên WEB01; mapping service được khai báo trong config, không suy ra tự động từ package.
- `feeds/epss_scores-current.csv.gz`: CSV gzip thật, số giả lập, model_version=synthetic-v1.
- `feeds/known_exploited_vulnerabilities.json`: catalog giả lập có count và metadata.
- `config.json`: offline=true, source_override=synthetic; đường dẫn tính từ vị trí config.

Dù file dùng tên cache chuẩn để tái sử dụng loader, chúng là fixtures bất biến. Demo không tải hoặc sửa chúng. `source_override` chỉ cho phép khai báo synthetic; không dùng để giả nguồn scanner thật.

## Đáp án mong đợi

Mỗi lần đều có **2 assets, 2 services, 3 findings, 0 connections, 0 exploit rules**.

| Thuộc tính | Lần 1 | Lần 2 |
|---|---|---|
| Package alpha / CVE-2099-0001 | EPSS 0.20, KEV false | EPSS 0.60, KEV true |
| Package beta / CVE-2099-0002 | Có | Không còn xuất hiện |
| Package gamma / CVE-2099-0003 | Có, KEV true | Giữ nguyên |
| Package delta / CVE-2099-0004 | Chưa có | Mới xuất hiện |
| Criticality DB01 | 4 | 5 |
| Phiên bản dịch vụ Web | 1.0 | 2.0 |

Diff: added_findings=1, removed_findings=1, persisting_findings=2, changed_findings=1, newly_kev=1, changed_assets=1, changed_services=1; các nhóm thêm/xóa tài sản, dịch vụ và kết nối đều bằng 0. “Không còn xuất hiện” không có nghĩa chắc chắn đã vá. KEV false chỉ nghĩa không có trong catalog mẫu của lần đó.

## Đọc kết quả

| File trong thư mục kết quả | Cách đọc |
|---|---|
| `run1/dataset.json`, `run2/dataset.json` | Snapshot canonical, dùng được với load_dataset |
| `run1/report.json`, `run2/report.json` | Counts, stage timing, input hashes, metadata feed, warnings và history |
| `history/index.json`, `history/runs/*/dataset.json` | Hai lần chạy được ghi lại |
| `verification.json` | passed=true, observed/expected, diff đầy đủ và thông tin history |
| `input-manifest.json` | SHA-256 toàn bộ bộ mẫu để nhận diện đầu vào chính xác |

Lần 2 report.history.previous_run_id phải trỏ lần 1. Các snapshot source và finding.source đều là synthetic. Warnings OFFLINE và SYNTHETIC_DATA là có chủ đích.

## Chạy pipeline từng bước

Nếu muốn xem CLI gốc (đầu ra cố định dưới outputs/sv1-manual):

```bash
uv run python -m sv1_data.pipeline data/samples/sv1_milestone1/run1/config.json
uv run python -m sv1_data.pipeline data/samples/sv1_milestone1/run2/config.json
```

Hai lệnh này dùng thời gian hiện tại và lịch sử hiện có; chạy lặp sẽ thêm lần chạy. Chúng không tự đối chiếu expected.json. Dùng runner demo khi cần một lượt nghiệm thu sạch, có kiểm tra đáp án và thời gian cố định. Không sửa fixture để thay đổi output_dir; copy config sang thư mục làm việc và điều chỉnh đường dẫn nếu cần.

## Giới hạn mốc 1

Chưa bổ sung topology/rules; bộ mẫu này chỉ nghiệm thu SV1, không dùng 0 đường để kết luận hệ thống an toàn. Chưa đổi định danh finding, chưa sửa toàn bộ merge conflict, history rule diff, online cache integrity hoặc transaction ghi nhiều file; các việc đó còn trong backlog đánh giá. Không có bằng chứng scanner thật hoặc Windows/Python 3.11 ở mốc này.

## Kiểm tra

```bash
uv run pytest tests/sv1_data -q
uv run ruff check sv1_data tests/sv1_data/test_sv1_milestone1.py
```

Kiểm thử mốc 1 chặn HTTP ở lớp gửi request, kiểm cả feed cũ/thiếu/hỏng, output đã tồn tại, snapshot tái lập và đáp án sai. Cài thư viện là bước chuẩn bị riêng, không nằm trong cam kết offline của pipeline.
