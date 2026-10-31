# SV1: hướng dẫn sử dụng

Phần SV1 (Asset & Vulnerability Intelligence) biến kết quả quét thành một `DatasetSnapshot`
hợp lệ cho SV2, SV3 và SV4. Hợp đồng dữ liệu nằm ở `common/schemas.py` và
`ARCHITECTURE.md` mục 6. Các lệnh trong tài liệu này viết cho Windows PowerShell; trên Linux hoặc
macOS đổi cách kích hoạt môi trường (`source .venv/bin/activate`) và cách đặt biến môi trường
(`export TÊN=giá_trị`), các lệnh `python -m ...` giữ nguyên.

## Các thành phần

| Thành phần | File | Việc làm |
|---|---|---|
| Hợp đồng, đọc và kiểm tra | `sv1_data/service.py` | `load_dataset`, `validate_dataset`, `save_dataset` |
| Adapter quét | `sv1_data/adapters/` | `nmap_xml.py`, `trivy_json.py`, `nuclei_jsonl.py` |
| Asset Inventory | `sv1_data/inventory.py` | Nhập tài sản từ CSV và ghép với kết quả quét |
| Làm giàu | `sv1_data/enrichment/` | EPSS, KEV, cache |
| Quy trình một lệnh | `sv1_data/pipeline.py` | Nối tất cả thành `dataset.json` và `report.json` |
| Lịch sử quét | `sv1_data/history.py` | So sánh hai lần chạy, lưu các lần chạy |
| Định danh | `sv1_data/identity.py` | `dataset_id` theo mã băm nội dung |
| Bản nháp LLM | `sv1_data/asset_draft.py` | Kiểm tra thuộc tính tài sản do LLM đề xuất |
| CSDL | `sv1_data/db.py`, `sv1_data/repository.py`, `migrations/` | Migration và kho lưu snapshot |
| Dữ liệu giả lập | `sv1_data/synthetic.py` | Bộ sinh có hạt giống cố định |

## Cài đặt

Python 3.11. Thư viện SV1 cần: `pydantic`, `httpx`, `sqlalchemy`, `psycopg2-binary`
(chỉ khi dùng PostgreSQL), cùng `pytest` và `ruff` để kiểm tra.

```powershell
uv venv --python 3.11
.venv\Scripts\Activate.ps1
uv pip install pydantic httpx sqlalchemy psycopg2-binary pytest ruff
```

## Đọc dữ liệu

```python
from pathlib import Path
from sv1_data.service import load_dataset

dataset = load_dataset(Path("data/samples/demo_lab_v1"))
```

`load_dataset` đọc `<thư mục>/dataset.json`, kiểm tra schema và mọi tham chiếu chéo rồi trả về
`DatasetSnapshot`. Lỗi được báo bằng các lớp trong `common/errors.py` (`ContractError`,
`InvalidReferenceError`, `UnsupportedVersionError`, `ResourceNotFoundError`).

Quy tắc về giá trị `null`: `null` nghĩa là **chưa biết**, không phải 0 hay false. Người dùng dữ
liệu (Risk Engine, bảng điều khiển) phải xử lý `null` một cách tường minh.

## Lệnh quét mẫu

Chỉ quét hệ thống của chính bạn. Thay `<thư mục kết quả>` bằng một thư mục NGOÀI repo:

```powershell
nmap -sT -sV -Pn -p 8080 -oX <thư mục kết quả>\nmap_dvwa.xml 127.0.0.1

docker run --rm -v //var/run/docker.sock:/var/run/docker.sock -v "<thư mục kết quả>:/out" -v trivy-cache:/root/.cache/ aquasec/trivy image --format json --output /out/trivy_dvwa.json <tên image>

docker run --rm -v "<thư mục kết quả>:/out" -v nuclei-templates:/root/nuclei-templates projectdiscovery/nuclei:latest -u http://host.docker.internal:8080 -jsonl -o /out/nuclei_dvwa.jsonl
```

Dòng Trivy gắn `docker.sock` để quét được cả image chỉ có trên máy. Không commit file quét thô: chúng
chứa nguyên văn HTTP và có thể chứa thông tin nhạy cảm.

## Các nguồn dữ liệu

| Nguồn | Đầu vào | Cho ra | Ghi chú |
|---|---|---|---|
| Inventory CSV | `asset_id,name,asset_type,internet_facing,criticality,sensitive_data,addresses` | `Asset` | Ô trống là chưa biết. Bắt buộc có `asset_id` và `name`. `internet_facing` và `sensitive_data` nhận true/false (cũng nhận yes/no, 1/0). `criticality` là số nguyên 1 đến 5. `addresses` là một hoặc nhiều IP ngăn cách bằng `\|` hoặc khoảng trắng, dùng để đổi IP trong kết quả quét thành `asset_id` |
| Nmap | `nmap -oX` | `Asset`, `Service` | Chỉ cổng mở tcp và udp |
| Trivy | `trivy image --format json` | `Finding` | Lỗ hổng cấp gói. `service_by_package` gắn gói với dịch vụ, mặc định để trống |
| Nuclei | `nuclei -jsonl` | `Finding` | Không bao giờ sao chép request, response, cookie. `min_severity`: `info`, `low`, `medium`, `high` hoặc `critical` |

## Quy trình một lệnh

```powershell
python -m sv1_data.pipeline cau_hinh.json
```

Đường dẫn trong file cấu hình được tính từ thư mục chứa file cấu hình. Ví dụ đầy đủ:

```json
{
  "dataset_id": "dvwa-lab-v1",
  "output_dir": "out/dvwa-lab-v1",
  "inventory_csv": "assets_lab.csv",
  "nmap_xml": ["nmap_dvwa.xml"],
  "trivy": [
    {
      "path": "trivy_dvwa.json",
      "asset_id": "WEB01",
      "service_by_package": {"apache2": "WEB01:tcp/8080"}
    }
  ],
  "nuclei": [
    {
      "path": "nuclei_dvwa.jsonl",
      "asset_id": "WEB01",
      "service_by_port": {"8080": "WEB01:tcp/8080"},
      "min_severity": "info"
    }
  ],
  "enrich": true,
  "cache_dir": "cache",
  "history_dir": "history",
  "database": false
}
```

Ghi chú về các khóa:

- Cần ít nhất một nguồn trong `inventory_csv`, `nmap_xml`, `trivy`, `nuclei`, `topology_json`.
- `topology_json` (không có trong ví dụ trên) là file `{"connections": [...], "exploit_rules": [...]}`
  do SV2 cung cấp. Chỉ thêm khi file đó có thật, nếu không chương trình báo không tìm thấy file.
- Nếu `enrich` là true và có `trivy` hoặc `nuclei` thì bắt buộc phải có `cache_dir`.
- `history_dir` bật lịch sử quét, `database` (true) lưu thêm vào CSDL, xem hai mục bên dưới.

Kết quả trong `output_dir`:

- `dataset.json`: snapshot hợp lệ. Nếu có bất kỳ tham chiếu sai, không file nào được ghi.
- `report.json`: số lượng bản ghi, thời gian từng bước, mã băm SHA-256 của file đầu vào, phiên bản
  EPSS và KEV, thống kê từng adapter, thay đổi so với lần chạy trước, cảnh báo.

`dataset_id` thật là tên gốc cộng 12 ký tự mã băm nội dung (ví dụ `dvwa-lab-v1-58f1463aaa0a`):
cùng dữ liệu thì cùng ID, dữ liệu đổi thì ID đổi. Xem `docs/decisions/sv1-0004-*.md`.

## Làm giàu EPSS và KEV

Chạy trong pipeline khi `enrich` là true. Dữ liệu được tải về `cache_dir` và dùng lại trong 24
giờ; mất mạng thì dùng bản cache cũ kèm cảnh báo. Có thể tải tay hai file vào `cache_dir` với đúng
tên `epss_scores-current.csv.gz` và `known_exploited_vulnerabilities.json`.

- Chỉ finding có mã dạng `CVE-YYYY-NNNN` được làm giàu. Mã khác giữ nguyên, mọi trường là `null`.
- `epss_probability` là `null` nếu CVE không có trong dữ liệu EPSS (không phải 0).
- `is_kev` là true nếu CVE có trong danh mục KEV, false nếu không có.
- Nguồn và phiên bản dữ liệu được ghi vào `evidence` (dòng bắt đầu bằng `epss:` và `kev:`).

## Lịch sử quét

Đặt `history_dir` trong cấu hình. Mỗi lần chạy được lưu thành `<history_dir>/runs/<run_id>/` (danh
sách các lần chạy nằm trong `<history_dir>/index.json`) và `report.json` ghi những gì đã thay đổi so
với lần trước: finding mới hoặc không còn xuất hiện, đổi điểm CVSS hay EPSS hay KEV (chênh lệch EPSS
không quá 0,01 bị coi là nhiễu), đổi ngữ cảnh tài sản, dịch vụ và kết nối. "Không còn xuất hiện"
chưa chắc là đã khắc phục (có thể lần quét sau không phủ hết).

## Dữ liệu giả lập tái lập được

```powershell
python -m sv1_data.synthetic --out data/samples/synthetic --seed 42 --sizes 10 50 200
```

Cùng `seed` cho cùng từng byte. Mọi bản ghi mang `source = "synthetic"` và mã lỗ hổng `SYN-NNNNN`.
Phân bố điểm được hiệu chỉnh theo một báo cáo Trivy thật nên chỉ là mô phỏng gần đúng.
`exploit_rules` để rỗng (thuộc SV2).

## Kiểm tra bản nháp thuộc tính tài sản do LLM đề xuất

```python
from sv1_data.asset_draft import apply_asset_attributes, validate_asset_attributes

clean = validate_asset_attributes({"criticality": 4, "internet_facing": None})
new_snapshot = apply_asset_attributes(dataset, "WEB01", clean)  # chỉ gọi sau khi người dùng xác nhận
```

Chỉ bốn thuộc tính được phép (`asset_type`, `internet_facing`, `criticality`, `sensitive_data`),
kiểm tra kiểu nghiêm ngặt: chuỗi như `"unknown"` bị từ chối, không bị coi là false. Snapshot mới có
`dataset_id` theo nội dung; snapshot cũ không bị sửa.

## Lưu trong CSDL (PostgreSQL)

```powershell
$env:APP_DATABASE_URL = "postgresql+psycopg2://nguoidung:matkhau@localhost:5432/vulnintel"
python -m sv1_data.db migrate
python -m sv1_data.repository save out/dvwa-lab-v1
python -m sv1_data.repository list
python -m sv1_data.repository export <dataset_id> <thư mục>
```

Hoặc đặt `"database": true` trong cấu hình pipeline để lưu ngay sau khi ghi `dataset.json` (cần đã
chạy `migrate` trước). Snapshot bất biến: lưu lại cùng nội dung thì không làm gì, cùng `dataset_id`
mà nội dung khác thì bị từ chối. Bảng được tạo bằng `migrations/*.sql`, không bao giờ tự tạo khi
chạy. Thông tin kết nối chỉ nằm trong biến môi trường `APP_DATABASE_URL`, không commit. Có thể thử
bằng SQLite: `sqlite:///duong/dan/test.db`.

## Kiểm thử

```powershell
python -m pytest tests/sv1_data -q
ruff check common sv1_data tests/sv1_data --line-length 100
ruff format common sv1_data tests/sv1_data --line-length 100 --check
```

Test chạy không cần mạng và không cần Docker (cơ sở dữ liệu dùng SQLite trong thư mục tạm).

## Giới hạn đã biết

- Finding của Trivy ở cấp gói: `service_id` là `null` trừ khi khai báo `service_by_package`
  (`docs/decisions/sv1-0003-*.md`).
- Điểm CVSS chỉ lấy bản v3; có thể `null` (`docs/decisions/sv1-0001-*.md`). Finding của Nuclei không
  có mã CVE thì không có điểm và không được làm giàu EPSS, KEV.
- KEV lấy từ bản sao GitHub của CISA (`docs/decisions/sv1-0002-*.md`).
- Dữ liệu EPSS đổi hằng ngày nên `dataset_id` có thể đổi mỗi ngày: đúng với quy tắc vì nội dung đã đổi.
- Chưa đọc cấu hình tập trung qua `common/config.py` (chưa có); `sv1_data/db.py` đọc biến môi trường
  trực tiếp.

## Xử lý sự cố thường gặp

| Hiện tượng | Nguyên nhân và cách xử lý |
|---|---|
| Tải KEV từ `cisa.gov` báo 403 | Trang chặn một số mạng. Mặc định đã dùng bản sao `cisagov/kev-data` trên GitHub |
| Chữ tiếng Việt vỡ khi `Get-Content` | PowerShell 5.1 đọc UTF-8 như ANSI. Thêm `-Encoding UTF8` |
| `ModuleNotFoundError` khi chạy `pytest` | Dùng `python -m pytest` từ thư mục gốc để `common` được tìm thấy |
| `enrich = true cần khai báo cache_dir` | Thêm `cache_dir`, hoặc đặt `enrich` là false |
| `dataset_id ... đã được dùng cho nội dung khác` | Bảo vệ tính bất biến; để pipeline tự sinh ID theo nội dung |
| `Chạy: python -m sv1_data.db migrate` | Bảng chưa được tạo; chạy migration trước khi lưu vào CSDL |
