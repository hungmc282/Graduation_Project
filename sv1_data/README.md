# SV1 — Dữ liệu tài sản và lỗ hổng

SV1 đọc kết quả scanner đã có, chuẩn hóa tài sản/dịch vụ/findings, ghép inventory,
bổ sung EPSS/KEV, kiểm tra và xuất snapshot. SV1 không chấm risk hoặc xác minh khai thác.

## Bắt đầu bằng bộ mẫu offline

Từ thư mục gốc repo:

```bash
uv sync --locked
uv run python -m sv1_data.demo
```

Bộ mẫu chạy hai lần nhập Nmap + Trivy + inventory, enrichment từ feed local,
xuất/nạp lại snapshot, lưu history và đối chiếu đáp án độc lập.
Đọc [hướng dẫn và kết quả mong đợi](../data/samples/sv1_milestone1/README.md).

## Các thành phần

| Thành phần | Vai trò |
|---|---|
| adapters/nmap_xml.py | XML scanner → assets/services |
| adapters/trivy_json.py | JSON scanner + mapping → findings |
| inventory.py | CSV ngữ cảnh + ánh xạ địa chỉ + merge assets |
| enrichment/ | Parse EPSS/KEV, cache, enrichment không mutate |
| service.py | Load/save/validate snapshot và tham chiếu |
| pipeline.py | Điều phối một lệnh, report và history |
| history.py | Lưu run và so sánh snapshots |
| synthetic.py | Sinh dữ liệu theo seed; không tạo exploit rules |
| demo.py | Hai lần chạy độc lập, kiểm chứng toàn luồng offline |

## Cấu hình mới ở mốc 1

`offline: true` chỉ đọc feed trong cache_dir, không tải cả khi file cũ. Thiếu/hỏng
feed thì báo lỗi. `source_override: "synthetic"` dùng cho đầu vào giả lập và đánh dấu
snapshot/findings; mặc định không override. Các trường cũ và schema snapshot giữ nguyên.

CLI tổng quát: `uv run python -m sv1_data.pipeline path/to/config.json`.
Đọc docstring pipeline.py để xem cấu hình; đường dẫn tương đối tính từ file config.

## Kiểm tra và hiện trạng

```bash
uv run pytest tests/sv1_data -q
uv run ruff check sv1_data
```

Mốc 1 là bản walkthrough chạy được; các vấn đề đã đánh giá còn lại và kế hoạch nghiên cứu
ở [hồ sơ kiểm kê](../docs/sv1-review/README.md). Không tuyên bố toàn bộ backlog đã hoàn tất.

## Mốc 2: dữ liệu sai và xung đột

Đã bổ sung validation đầu vào Nmap/Trivy và fail-on-conflict giữa các quan sát
scanner. Duplicate giống hệt được thống kê trong report.merge_stats; ID finding
không thay đổi. Xem [chính sách, ví dụ lỗi và hướng dẫn xử lý](../docs/sv1/milestone2-input-and-merge.md).
