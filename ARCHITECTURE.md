# Quy chuẩn kiến trúc và phát triển toàn dự án

**Contract version: 1.0.0 — bản đề xuất để cả nhóm duyệt và áp dụng.**

Đây là nguồn quy chuẩn chung cho toàn bộ vòng đời dự án, dành cho sinh viên và công cụ AI viết code. Không gắn với tuần hoặc tiến độ. Các mục chưa hiện thực là yêu cầu đích, không phải xác nhận hệ thống đã có sẵn. Trước khi hợp đồng được ghép vào main, cả nhóm cần xác nhận hoặc sửa qua PR.

## 1. Quy tắc bắt buộc đối với người và AI

1. Đọc tài liệu này, `CONTRIBUTING.md`, README và mã hiện có trước khi thêm/sửa code.
2. Dùng đúng thuật ngữ, trường dữ liệu, chữ ký hàm và trách nhiệm module đã quy định. Không tự tạo tên tương đương như `host_id`, `machine_id` thay `asset_id` trong dữ liệu chuẩn.
3. Import và tái sử dụng schema chung; không định nghĩa bản sao ở từng subsystem.
4. Dữ liệu scanner và tên trường bên ngoài phải được chuyển đổi trong adapter. Không bắt module khác hiểu định dạng riêng của nguồn ngoài.
5. Nếu hợp đồng chưa đủ, đề xuất bổ sung vào hợp đồng và schema chung; không âm thầm đoán hoặc đổi kiểu dữ liệu.
6. Không đưa tính toán graph/risk vào UI hoặc prompt. LLM không quyết định điểm hay ranking.
7. Không viết code gọi hàm chưa tồn tại rồi tuyên bố đã tích hợp. Nếu chưa có module thật, fixture/mock phải ghi rõ và tuân theo schema.
8. Thay đổi phải kèm hướng dẫn chạy và kiểm tra phù hợp. Không tuyên bố chạy mượt chỉ vì push thành công.
9. Hướng dẫn này áp dụng cho mã mới. Mã cũ không khớp phải được chuyển đổi có kiểm soát, không duy trì nhiều hợp đồng song song không có adapter.

## 2. Ngôn ngữ, nền tảng và công nghệ

| Nội dung | Chuẩn chung |
|---|---|
| Ngôn ngữ backend/engine | Python 3.11.x; dùng tính năng tương thích Python 3.11 |
| Tên mã nguồn, schema, API, Git branch | Tiếng Anh; quy tắc ở mục 3 |
| UI, hướng dẫn sử dụng, giải thích/báo cáo | Tiếng Việt; giữ nguyên ID và thuật ngữ kỹ thuật khi cần |
| Encoding | UTF-8; file text LF, kết thúc bằng newline |
| Backend HTTP | FastAPI, API prefix `/api/v1` |
| UI | Streamlit cho prototype; nếu chuyển framework phải giữ hợp đồng API/dữ liệu và có quyết định kiến trúc |
| Graph | Python/NetworkX cho phân tích; nếu thêm Neo4j vẫn giữ facade của SV2 |
| Cơ sở dữ liệu chính | PostgreSQL; truy cập bằng repository, thay đổi schema có migration |
| LLM | Ollama chạy local; URL/model là cấu hình, không hard-code theo máy |
| Triển khai | Docker Compose cho dịch vụ nền/backend; Ollama trên Mac chạy native để sử dụng GPU |
| Kiểm tra | pytest cho nghiệp vụ/tích hợp, Ruff cho lint/format |

Phiên bản chính xác của thư viện được khóa trong dependency lock sau khi kiểm tra chung; tài liệu này không tự nhận các phiên bản mới nhất. Một file `pyproject.toml` ở gốc là nguồn dependency và cấu hình công cụ; dùng `uv` và commit `uv.lock`. Nếu repo chuyển từ requirements.txt, phải chuyển có kiểm tra và cập nhật README cùng PR; không duy trì hai danh sách nguồn độc lập.

Lệnh chuẩn sau khi cấu hình đã được hiện thực:

```bash
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv run streamlit run sv4_app_llm/app.py
uv run uvicorn sv4_app_llm.api:app --host 127.0.0.1 --port 8000
```

Không coi các lệnh này là đã hoạt động khi pyproject, lockfile hoặc entry point chưa được tạo. Mỗi PR tích hợp phải bảo đảm lệnh liên quan thực sự chạy.

## 3. Quy tắc đặt tên

| Đối tượng | Quy tắc | Ví dụ |
|---|---|---|
| File, package, biến, hàm, tham số | `snake_case`, tiếng Anh | `asset_id`, `build_graph`, `risk_engine.py` |
| Class, Pydantic model, exception | `PascalCase` | `Asset`, `AnalysisResult`, `ContractError` |
| Hằng số | `UPPER_SNAKE_CASE` | `DEFAULT_TIMEOUT_SECONDS` |
| Biến môi trường | Prefix `APP_`, `UPPER_SNAKE_CASE` | `APP_OLLAMA_MODEL` |
| Bảng SQL | Số nhiều, `snake_case` | `assets`, `findings`, `attack_paths` |
| Cột SQL / khóa JSON | Cùng tên canonical | `asset_id`, `finding_id` |
| URL | Danh từ số nhiều; nhiều từ dùng dấu gạch nối | `/api/v1/attack-paths` |
| Test file / hàm test | `test_*.py` / `test_*` | `test_patch_simulation.py` |
| ID | Chuỗi không rỗng, không suy nghĩa từ định dạng | `WEB01`, UUID dạng chuỗi |
| Thời điểm | Tên kết thúc `_at`, UTC có timezone | `created_at` |
| Thời lượng | Có đơn vị | `timeout_seconds`, `duration_ms` |
| Xác suất | Tên có nghĩa, miền 0–1 | `epss_probability` |

Không dùng tên tiếng Việt không dấu, tên viết tắt mơ hồ (`dt`, `rs`, `obj1`), hoặc cùng tên cho hai ý nghĩa. CVSS/EPSS/KEV là viết tắt lĩnh vực được phép. Không đặt file `json.py`, `typing.py`, `streamlit.py`, `ollama.py` để tránh che thư viện.

Các thuật ngữ chuẩn:

- `asset`: tài sản; `service`: dịch vụ trên tài sản; `vulnerability`: định danh lỗ hổng; `finding`: phát hiện trên tài sản/dịch vụ cụ thể.
- `connection`: khả năng kết nối có hướng; không đồng nghĩa khai thác thành công.
- `attack_path`: chuỗi bước khai thác có điều kiện; `critical_asset`: tài sản đích quan trọng.
- `risk_score`: điểm do Risk Engine; `remediation_impact`: rủi ro trước trừ sau; `priority_rank`: thứ hạng.
- `explanation`: diễn giải kết quả; không phải phép tính mới.

## 4. Cấu trúc và quyền sở hữu

```text
Graduation_Project/
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── README.md
├── pyproject.toml
├── uv.lock
├── .env.example
├── common/                   # Hợp đồng chung, không thuộc riêng một SV
│   ├── schemas.py           # Pydantic models, enums, constraints
│   ├── errors.py            # Exception và error codes
│   └── config.py            # Đọc cấu hình một lần
├── sv1_data/                # SV1: asset, scanner, validation, enrichment
├── sv2_attack_graph/        # SV2: graph, reachability, path, simulation
├── sv3_risk/                # SV3: scoring, propagation, prioritization
├── sv4_app_llm/             # SV4: app, API, orchestration, LLM, reporting
├── data/samples/            # Fixture công khai, synthetic, có version
├── tests/                   # Chia theo module + integration + contracts
├── migrations/             # Migration DB có thứ tự
├── docs/decisions/          # Quyết định kiến trúc có lý do
└── deployment/              # Dockerfile/Compose và hướng dẫn
```

Cấu trúc là đích thống nhất, tạo file con khi cần. Không tạo một bản project khác trong mỗi thư mục SV. Mỗi package Python có `__init__.py`. Import tuyệt đối từ gốc: `from common.schemas import Asset`; không sửa `sys.path`, không dùng đường dẫn cá nhân.

| Chủ sở hữu | Trách nhiệm | Không làm thay |
|---|---|---|
| SV1 | Thu thập, asset/service/finding, normalize, enrich, repository dữ liệu nguồn | Graph hoặc ranking |
| SV2 | Reachability, exploit rules, graph, paths, giả lập trạng thái đã vá | Công thức risk |
| SV3 | Risk model minh bạch, propagation, RI, ranking, baselines | Sửa graph bằng logic riêng, gọi LLM để chấm điểm |
| SV4 | Điều phối qua facade, API/UI, Ollama, extraction/explanation/report, deployment | Viết lại thuật toán SV1–3 |

SV4 điều phối `common/`; chủ module cung cấp và bên nhận đều phải duyệt thay đổi hợp đồng. Người điều phối dependency/cấu hình được nhóm chỉ định, không mặc định được tự đổi mọi phần.

## 5. Chiều phụ thuộc và luồng nghiệp vụ

```text
SV1 → DatasetSnapshot → SV2 → GraphResult
DatasetSnapshot + GraphResult → SV3 → AnalysisResult
SV4 gọi facade SV1/SV2/SV3 → hiển thị / giải thích / báo cáo
LLM extraction → bản nháp → xác nhận + validate SV1 → snapshot mới
```

Các module đều được import `common`. SV2 không import SV3 hoặc UI. SV3 chỉ gọi facade SV2; SV1 không import module downstream. Không circular import.

UI không truy cập DB trực tiếp và không chứa risk formula. API/UI cùng dùng service điều phối để không có hai luồng tính khác nhau. Giao diện có thể gọi service Python trực tiếp; frontend khác gọi API nhưng giữ cùng kiểu dữ liệu.

## 6. Schema và quy tắc chung

`common/schemas.py` là nguồn kiểu thực thi duy nhất; dùng Pydantic v2, strict validation cho dữ liệu canonical, `extra="forbid"` trên model truyền giữa module. Adapter CSV/API ngoài được phép chuyển kiểu trước validation. Tài liệu này định nghĩa hợp đồng cần hiện thực, chưa tạo sẵn models.

- Facade nhận/trả Pydantic models, không dùng dict không kiểm tra. Serialize qua `model_dump(mode="json")`; nạp qua `model_validate`.
- Mọi envelope snapshot/graph/analysis/LLM response có `schema_version: str`, hiện là `1.0.0`.
- Trường nullable vẫn phải có, giá trị null nghĩa chưa biết. Trường optional có default phải khai báo rõ trong model; không tự thêm default làm thay đổi nghiệp vụ.
- Không dùng NaN/Infinity trong JSON. Không dùng string cho số/boolean trong dữ liệu canonical.
- Thời điểm dùng datetime UTC có timezone; serialized ISO 8601. ID giữ nguyên hoa/thường; adapter trim khoảng trắng, không tự gộp ID.
- Enum dùng chuỗi chữ thường. Risk thang nào phải có metric/model version; không so sánh score khác thang một cách ngầm định.
- Enum giá trị `source`: `synthetic`, `scanner`, `manual`, `mixed`. Finding chỉ dùng ba giá trị đầu; dataset có thể mixed.
- Không thiếu dữ liệu bằng cách bịa 0. Thiếu trường ảnh hưởng tính toán thì báo lỗi hoặc dùng chính sách xử lý thiếu được phiên bản hóa và nêu warning.

### 6.1 Asset và Service — SV1

| Model | Trường canonical |
|---|---|
| Asset | `asset_id: str`, `name: str`, `asset_type: str | None`, `internet_facing: bool | None`, `criticality: int | None` (1–5), `sensitive_data: bool | None` |
| Service | `service_id: str`, `asset_id: str`, `protocol: tcp | udp`, `port: int` (1–65535), `product: str | None`, `product_version: str | None` |

Không suy ra criticality chỉ từ tên máy. Unknown enum/kiểu tài sản chưa chuẩn hóa dùng asset_type null và giữ bằng chứng ở metadata nguồn ngoài canonical.

### 6.2 Finding — SV1

| Trường | Kiểu / nghĩa |
|---|---|
| finding_id | str, định danh duy nhất của finding |
| asset_id | str, tham chiếu asset tồn tại |
| service_id | str hoặc null; nếu có phải thuộc đúng asset |
| vulnerability_id | str, CVE hoặc mã synthetic; không dùng thay finding_id |
| cvss_score | float hoặc null, 0–10 |
| epss_probability | float hoặc null, 0–1 |
| is_kev | bool hoặc null |
| source | synthetic / scanner / manual |
| evidence | list[str], có thể rỗng; tham chiếu/miêu tả đã lọc dữ liệu nhạy cảm |
| observed_at | datetime UTC hoặc null |
| enriched_at | datetime UTC hoặc null |

Chuẩn chính thức dùng `cvss_score`, không dùng `cvss` như ví dụ thảo luận trước. SV1 chịu trách nhiệm adapter chuyển dữ liệu cũ. Điểm CVSS chuẩn hóa không thay bản ghi nguồn/thông tin phiên bản CVSS; khi cần phân biệt phiên bản bổ sung trường có kiểm soát.

### 6.3 Connection và ExploitRule — SV2

Connection: `connection_id: str`, `source_asset_id: str`, `target_asset_id: str`, `target_service_id: str | None`, `allowed: bool`, `evidence: list[str]`.

`INTERNET` là ID điểm vào đặc biệt ở source, không phải asset. Đích phải là asset tồn tại. target_service nếu có phải thuộc đích. Có hướng, không tự sinh chiều ngược.

ExploitRule: `rule_id: str`, `source_asset_id: str`, `target_asset_id: str`, `required_finding_id: str | None`, `required_state: str`, `resulting_state: str`, `rule_type: exploit | trust`, `evidence: list[str]`.

Rule phải có kết nối/quyền truy cập phù hợp và trạng thái trước/sau rõ. `required_finding_id=null` chỉ dùng với trust có bằng chứng, không tự giả định không cần khai thác. Exploit phải tham chiếu finding của đích. Bộ rule có phiên bản và được SV2 kiểm tra. Đây là abstraction giới hạn; rule engine phải công bố loại tấn công hỗ trợ và giả định, không khẳng định bao phủ mọi CVE.

### 6.4 DatasetSnapshot

Trường: `schema_version`, `dataset_id: str`, `created_at: datetime`, `source`, `assets: list[Asset]`, `services: list[Service]`, `findings: list[Finding]`, `connections: list[Connection]`, `exploit_rules: list[ExploitRule]`.

Snapshot bất biến về nội dung. SV1 sở hữu loader; SV2 cung cấp topology/rules đúng schema để được validate cùng snapshot. Đổi dữ liệu phải đổi dataset_id; lưu nội dung/hash để kiểm tra. Không tái sử dụng ID cho nội dung khác.

### 6.5 GraphResult và AttackPath — SV2

GraphResult: `schema_version`, `dataset_id`, `graph_model_version: str`, `patched_finding_ids: list[str]`, `entry_point_ids: list[str]`, `target_asset_ids: list[str]`, `paths: list[AttackPath]`, `search_complete: bool`, `warnings: list[str]`.

AttackPath: `path_id: str`, `target_asset_id: str`, `asset_ids: list[str]` (bao gồm điểm vào nếu có), `rule_ids: list[str]` theo thứ tự, `finding_ids: list[str]`.

Path ID ổn định theo chuỗi rule, không đánh số lại khi path khác mất. Quy tắc cycle, max depth và search budget thuộc graph config được phiên bản hóa. Hết budget: `search_complete=false`, không được coi là không có đường. Graph không mutate snapshot. Finding không tồn tại trong yêu cầu vá phải báo lỗi.

### 6.6 AnalysisResult và PriorityItem — SV3

AnalysisResult gồm:

- `schema_version`, `dataset_id`, `analysis_id: str`, `created_at: datetime`.
- `graph_model_version: str`, `risk_model_version: str`, `config_hash: str`.
- `patched_finding_ids: list[str]`, `target_asset_ids: list[str]`.
- `ranking_metric: critical_paths_blocked | remediation_impact`.
- `risk_score_status: not_implemented | complete | incomplete`.
- `risk_before: float | None` (không âm), `baseline_cvss_order: list[str]`.
- `results: list[PriorityItem]`, `warnings: list[str]`.

PriorityItem gồm:

| Trường | Kiểu / quy tắc |
|---|---|
| finding_id, asset_id | str |
| cvss_score | float hoặc null, 0–10 |
| paths_before, paths_after, paths_blocked | int không âm, paths_blocked = before − after trong mô hình chỉ loại bước |
| blocked_path_ids | list[str], không trùng, khớp paths_blocked |
| risk_after | float không âm hoặc null |
| remediation_impact | float hoặc null; risk_before − risk_after |
| priority_rank | int từ 1; null khi không đủ dữ liệu xếp hạng |
| reason_codes | list[str] có giải thích trong risk model documentation |

Đồng giá trị theo ranking_metric dùng dense rank 1,1,2. Hiển thị phụ bằng finding_id không phá đồng hạng. Nếu có tie-break theo nghiệp vụ, phải chốt và phiên bản hóa, không tự dùng CVSS. CVSS baseline là phương pháp riêng; null cuối bảng và có warning.

Không cộng RI của từng finding để tính hiệu quả vá nhóm vì có thể chung path. Từng phương án thử từ cùng trạng thái hiện tại. `results` không chứa finding đã vá. Snapshot hoặc search không đầy đủ thì kết quả mang trạng thái incomplete và warning; không ghi complete hoặc cam kết tối ưu toàn hệ thống.

Score thật cần tài liệu công thức, thang điểm, tham số, cách xử lý missing và cộng trùng. Khi chưa có score, risk_before/risk_after/RI phải null, không giả 0. Đếm đường chỉ được dùng ranking_metric tương ứng. ID phân tích phải gắn với dataset, phiên bản model, config và tập patched; khi thay đầu vào phải đổi ID. Timestamp không phải yếu tố tính điểm.

### 6.7 LLM và reporting — SV4

ExplanationRequest: `analysis: AnalysisResult`, `graph_result: GraphResult`, `selected_finding_ids: list[str]`. Kiểm tra cùng dataset, graph version và patched state. IDs phải thuộc analysis; danh sách rỗng nghĩa giải thích toàn kết quả.

ExplanationResult: `schema_version`, `analysis_id`, `status: ok | unavailable | invalid_output`, `text: str`, `referenced_finding_ids: list[str]`, `missing_information: list[str]`, `model_id: str`, `prompt_version: str`, `warnings: list[str]`.

LLM không sinh score hoặc priority_rank để ghi đè engine. JSON hợp lệ chưa chứng minh câu chữ đúng; kiểm tra ID/số liệu và bộ đáp án chuyên môn. Cache theo analysis_id + selected IDs + model digest + prompt version + options. Thay bất kỳ thành phần nào phải vô hiệu kết quả cũ. Không gọi AI tự động mỗi lần UI rerun.

Extraction trả bản nháp: `draft_id`, `description`, `proposed_attributes`, `field_evidence`, `missing_fields`. Chỉ cho phép các thuộc tính asset đã định nghĩa; SV1 validate và người dùng xác nhận trước tạo snapshot. Không đoán criticality hoặc coi unknown là false.

Báo cáo sử dụng AnalysisResult đã lưu và explanation có cùng analysis_id; ghi dataset/model versions, thời điểm, phạm vi, warnings và nguồn dữ liệu. LLM không phải nguồn sự thật về bản vá; thông tin khắc phục cụ thể cần tài liệu phù hợp sản phẩm/phiên bản và nguồn được lưu.

## 7. Facade công khai giữa các subsystem

Hiện thực/export các hàm trong `sv1_data/service.py`, `sv2_attack_graph/service.py`, `sv3_risk/service.py`, `sv4_app_llm/service.py`. Nội bộ người phụ trách tự chia file, nhưng bên khác chỉ import service, không import hàm private.

```python
# SV1
load_dataset(data_dir: Path) -> DatasetSnapshot
validate_dataset(dataset: DatasetSnapshot) -> None

# SV2
build_graph(dataset: DatasetSnapshot,
            patched_finding_ids: list[str],
            config: GraphConfig) -> GraphResult

# SV3; gọi SV2 qua facade, không tự sửa graph
analyze(dataset: DatasetSnapshot,
        patched_finding_ids: list[str],
        graph_config: GraphConfig,
        risk_config: RiskConfig) -> AnalysisResult

# SV4
explain_analysis(request: ExplanationRequest) -> ExplanationResult
```

Các kiểu cùng nằm trong common.schemas. `GraphConfig`: `model_version`, `entry_point_ids`, `target_asset_ids`, `max_depth` (int >0), `max_paths` (int >0). `RiskConfig`: `model_version`, `ranking_metric`, `parameters: dict[str, float]`; SV3 validate tên/miền tham số theo đúng model version và từ chối tham số lạ. Không để model_version/config là chuỗi hiển thị không ảnh hưởng logic.

Caller truyền `patched_finding_ids=[]` khi chưa vá; không dùng mutable default. Hàm core đồng bộ, không gọi network hoặc LLM trong vòng tính điểm. I/O enrichment tách riêng và ghi nhận dữ liệu vào snapshot trước phân tích. Kết quả phân tích dùng snapshot đã cố định để tái lập.

## 8. API và định dạng lỗi

API là lớp bọc service; không có scoring riêng. Các endpoint được hiện thực khi cần, không phải tạo hết ngay:

| Endpoint | Mục đích |
|---|---|
| `GET /api/v1/health` | Backend sống, không bắt buộc Ollama hoạt động |
| `GET /api/v1/datasets/{dataset_id}` | Lấy snapshot đã lưu |
| `POST /api/v1/analyses` | Nhận dataset_id, patched_finding_ids, graph_config, risk_config; trả AnalysisResult |
| `GET /api/v1/analyses/{analysis_id}` | Lấy kết quả đã lưu |
| `POST /api/v1/explanations` | Nhận analysis_id và selected_finding_ids; backend nạp graph đúng provenance rồi gọi LLM |

Nếu phân tích chưa lưu GraphResult, dựng lại với cùng snapshot/config và kiểm tra provenance trước giải thích. Khi chuyển sang background job phải bổ sung hợp đồng Job riêng; không thay âm thầm response AnalysisResult bằng job_id.

Thành công trả model JSON trực tiếp, không nơi bọc `data` nơi không. Lỗi HTTP có dạng:

```json
{
  "error": {
    "code": "INVALID_REFERENCE",
    "message": "Finding tham chiếu tài sản không tồn tại.",
    "details": [{"field": "asset_id", "record_id": "F01"}],
    "request_id": "req-example"
  }
}
```

Mapping: validation/contract 422, not found 404, conflict/version không hỗ trợ 409, dịch vụ phụ thuộc không sẵn sàng 503, lỗi bất ngờ 500. Exception core định nghĩa ở common.errors: `ContractError`, `InvalidReferenceError`, `UnsupportedVersionError`, `ResourceNotFoundError`. Handler chung chuyển cả lỗi validation FastAPI sang cùng envelope. Không trả stack trace, credentials hoặc dữ liệu scan nhạy cảm ra UI.

Không coi exception là `paths=[]` hoặc score 0. Warnings dùng cho kết quả có giới hạn; lỗi ngăn tính toán phải dừng và báo rõ.

## 9. Cấu hình, lưu trữ và môi trường

`common/config.py` đọc biến môi trường một lần, tạo settings object được truyền hoặc import dùng chung:

| Biến | Ý nghĩa / mặc định local |
|---|---|
| APP_ENV | `local` |
| APP_DATA_DIR | `data/samples`, resolve theo repo root |
| APP_DATABASE_URL | Do môi trường cung cấp, không có mật khẩu mặc định trong source |
| APP_OLLAMA_BASE_URL | `http://localhost:11434` khi chạy native |
| APP_OLLAMA_MODEL | Tên model local được nhóm kiểm tra; ví dụ `qwen3:14b` |
| APP_LLM_TIMEOUT_SECONDS | `120`, số dương |
| APP_LOG_LEVEL | `INFO` |

Container gọi Ollama native trên Mac qua hostname host do Compose cấu hình, không dùng localhost container. Commit `.env.example` với giá trị mẫu; không commit `.env`. Giá trị giả lập không được dùng ngầm cho production/lab thật.

Cấu hình graph/risk là input phân tích có phiên bản, không rải trọng số trong app hoặc biến môi trường không được lưu cùng kết quả. Repository persistence thuộc chủ dữ liệu; module khác dùng repository/service thay vì tự mở connection SQL. Migration do chủ model đề xuất, người điều phối duyệt. Không tự tạo/sửa bảng khi UI chạy.

Không commit model weights, .venv, logs, DB dump nhạy cảm. Fixture nhỏ, synthetic, có manifest schema_version/dataset_id được commit. Outputs và dữ liệu thật ở vùng ignored có cấu hình. Backup/migration phải được mô tả trước thay đổi DB phá vỡ.

## 10. Chất lượng và khả năng tái lập

- Type hints cho facade và hàm nghiệp vụ. Docstring nêu điều kiện, đơn vị, giá trị null và ngoại lệ.
- Code 4 spaces; line length 100; cấu hình Ruff chung ở pyproject. Không tự đổi formatter từng subsystem.
- Logging dùng logging chung, có dataset_id/analysis_id khi phù hợp; không ghi toàn prompt/secret hoặc dữ liệu nhạy cảm mặc định.
- Không hard-code IP cá nhân, đường dẫn Downloads hoặc danh sách finding của demo vào thuật toán tổng quát. Demo rules là dữ liệu có phiên bản.
- Randomness nếu có phải seed/config hóa và được lưu; thứ tự tập/dict không quyết định kết quả ranking.
- Ghi cùng analysis: snapshot/config hash, phiên bản graph/risk, code commit và dependency lock dùng thực nghiệm. LLM lưu model digest/prompt version/options; không cam kết câu chữ tái lập tuyệt đối.

Kiểm tra bắt buộc trước merge code:

1. Lint và format chung.
2. Schema contract: fixture validate, serialization round trip, từ chối trường sai/phiên bản không hỗ trợ.
3. Các quy tắc nghiệp vụ thay đổi: ví dụ bước bị chặn, trạng thái quyền, đồng hạng, không mutate input.
4. Tích hợp khi có đủ subsystem: load → graph → analyze; không phụ thuộc Ollama hoặc Internet trong CI mặc định.
5. Mock/stub LLM theo hợp đồng cho CI; chạy model thật trong đánh giá riêng, lưu chất lượng và độ trễ.

Pipeline CI thực thi các lệnh ở mục 2 và kiểm tra hợp đồng trước khi main được coi là sẵn sàng ghép. Bắt buộc status checks trên GitHub chỉ sau khi workflow tồn tại và đã chạy; tài liệu không tự bật branch protection.

## 11. Git, PR và thay đổi hợp đồng

Giữ bốn nhánh: `sv1-data`, `sv2-attack-graph`, `sv3-risk`, `sv4-app-llm`; main là bản tích hợp. Chi tiết cập nhật/merge ở CONTRIBUTING.md. Commit có dạng `feat(data): ...`, `fix(graph): ...`, `docs(architecture): ...`. Không thêm nhánh mặc định khác nếu chưa thống nhất.

PR phải nêu module bị ảnh hưởng, cách chạy, kiểm tra, schema/config changes và giới hạn. Không push thẳng main, force push hoặc sửa cùng file chung khi chưa phối hợp. Merge contract trước để mọi người có cùng chuẩn, sau đó tích hợp module theo hợp đồng.

Version hợp đồng dùng SemVer: vá tài liệu/lỗi không đổi nghĩa tăng patch; tính năng tương thích có default rõ tăng minor; đổi tên/kiểu/ý nghĩa trường hoặc chữ ký hàm phá vỡ tăng major. Với strict extra=forbid, thêm trường cũng cần bên nhận cập nhật schema trước; không tự coi là tương thích runtime chỉ vì tăng minor. Mỗi release chỉ nhận các version đã công bố hỗ trợ; không tự strip trường lạ để chạy tiếp.

Đổi hợp đồng cần: đề xuất → người cung cấp và người nhận duyệt → sửa tài liệu + common schemas + fixture + adapter/migration + tests → cập nhật các consumer trong cùng kế hoạch chuyển đổi. Không yêu cầu mỗi người tự sửa tên biến để ghép.

Quyết định lớn (đổi UI framework, storage, risk formula, cách đếm path) lưu ngắn tại docs/decisions với bối cảnh, lựa chọn và ảnh hưởng. Tài liệu này không viết lại khi hoàn thành một giai đoạn; chỉ cập nhật khi quyết định kiến trúc/hợp đồng thực sự thay đổi.

## 12. Danh sách nghiệm thu đồng bộ cho mọi PR tích hợp

- [ ] Tên và kiểu khớp common schemas; không có alias canonical tự tạo.
- [ ] Input/output facade khớp, không import private cross-module.
- [ ] Cùng dataset/config cho cùng kết quả engine; giả định và dữ liệu thiếu minh bạch.
- [ ] Simulation không sửa dữ liệu gốc; các phương án độc lập không cộng dồn ngầm.
- [ ] UI chỉ hiển thị, không tự tính điểm hoặc phá đồng hạng.
- [ ] LLM không sửa kết quả và không ảnh hưởng khả năng xem kết quả core khi lỗi.
- [ ] Cấu hình không hard-code theo máy; dependencies/migration được cập nhật nếu cần.
- [ ] Check phù hợp chạy được; phần chưa hiện thực được ghi rõ.
- [ ] Không có secret/model weights/dữ liệu nhạy cảm trong diff.
- [ ] Người nhận module kiểm tra được ví dụ bàn giao và duyệt PR.

**Lưu ý triển khai:** tài liệu thống nhất cách viết nhưng không tự làm các module tương thích. Cần hiện thực common schemas, fixture hợp lệ và CI kiểm tra hợp đồng để phát hiện lệch chuẩn trước khi merge. Đây là điều kiện để ghép ổn định mà không sửa tên biến thủ công giữa các sinh viên.
