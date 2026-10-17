# Use Cases — Risk & Prioritization Engine

| Thuộc tính | Giá trị |
|---|---|
| Người phụ trách | Trần Gia Bảo — SV3 |
| Phiên bản / ngày | 1.0.0 / 2026-10-18 |
| Checklist | Tuần 1 — Ngày 2 |
| Trạng thái | Đặc tả hành vi để review; không xác nhận UI/API toàn nhóm đã triển khai |
| Tham chiếu | SV3_SCOPE.md; THREAT_MODEL.md; bộ chuẩn hóa v2; RISK_MODEL_V1.md |

## 1. Actors và quy ước

- Người phân tích: chọn snapshot/targets/config, xem ranking, yêu cầu what-if.
- Platform/orchestrator SV4: caller kỹ thuật, nạp dữ liệu, gọi facades, lưu/hiển thị.
- SV1: cung cấp snapshot/metadata hợp lệ. SV2: cung cấp graph/paths theo tập vá.
- Người quản trị/người review: xem cơ sở ưu tiên và đánh giá giả định/kết quả.

S là tập finding đã mô phỏng vá. Ban đầu S rỗng. Target mặc định của fixture là DB01;
không ngầm áp dụng target này cho mọi dữ liệu thật. Mọi số minh họa dưới đây thuộc
diamond-v1/reference-lab-v1/context-path-v1, các default weights đã công bố.
Risk là heuristic index, không xác suất. UI/API là lớp tích hợp SV4, không nơi tính score.

## 2. UC-01 — Xem và so sánh ưu tiên khắc phục

**Mục tiêu:** so sánh thứ tự theo CVSS với tác động giảm risk có xét đường tấn công.

**Actor chính:** người phân tích; **caller:** SV4.

**Tiền điều kiện:** snapshot và config đã validate; đủ dữ liệu theo strict risk policy;
service SV2 hỗ trợ graph config, có thể trả complete paths; target/entry hợp lệ.

**Trigger/input:** người dùng yêu cầu phân tích snapshot; input `dataset`, S,
`graph_config`, `risk_config`. Full model dùng `context-path-v1/remediation_impact`.

**Luồng chính:**
1. SV4 nạp đúng snapshot bất biến và truyền shared models vào `analyze`.
2. SV3 kiểm type/references/config/readiness và tập vá.
3. SV3 gọi SV2 để dựng graph tại S; kiểm provenance, stable path IDs và completeness.
4. SV3 tính local components, propagation, path/target/system risk và importance.
5. Với từng finding f chưa vá, SV3 gọi graph tại S hợp {f}, tính risk_after và marginal RI.
6. SV3 tạo dense rank theo RI, không dùng CVSS phá tie; tính đủ 4 baseline riêng.
7. SV4 nhận AnalysisResult và details sidecar cùng ID, lưu provenance và hiển thị.

**Output/hậu điều kiện:** ranking, risk_before, risk_after/RI từng item, path counts/IDs,
reason_codes, versions/hash/warnings; snapshot không bị thay đổi. Details cung cấp
components/path steps/target risk/baselines/assumptions. Không có hành động patch thật.

**Tiêu chí chấp nhận diamond chưa vá:**

| Finding | CVSS | RI | Paths bị chặn | Hạng RI |
|---|---:|---:|---:|---:|
| F01 | 7.5 | 41.2825 | 2 | 1 |
| F02 | 8.0 | 17.6925 | 1 | 2 |
| F03 | 9.8 | 0 | 0 | 3 |
| F04 | 6.0 | 0 | 1 | 3 |

Baseline CVSS có thứ tự F03 → F02 → F01 → F04. risk_before=41.2825.
F03/F04 đồng hạng theo RI, dù F04 loại được một path yếu. UI phải giữ sự khác biệt
giữa path count và risk impact; không tự nâng hạng F04 bằng tie-break chưa được chốt.

**Ngoại lệ:** dữ liệu thiếu/sai, version unsupported, SV2 unavailable hoặc search
incomplete chuyển UC-06; không trả score0/ranking mới như một phân tích thành công.

## 3. UC-02 — What-if Patch một finding

**Mục tiêu:** biết tác động giả định trước khi quyết định khắc phục thật.

**Actor:** người phân tích qua SV4. **Tiền điều kiện:** UC-01 có kết quả hợp lệ;
finding được chọn thuộc snapshot và chưa nằm trong S.

**Input:** snapshot/config đã phân tích, S, finding được chọn f.

**Luồng chính:**
1. SV4 giữ kết quả trước vá và provenance; xác nhận finding thuộc đúng snapshot.
2. Tạo tập mô phỏng mới S' = S hợp {f}, không sửa dữ liệu nguồn.
3. Gọi engine trên S' để có risk và ranking ứng viên còn lại.
4. So risk/path trước–sau trên cùng target set/model/config.
5. Hiển thị tập đã vá, các path mất/còn, RI và cảnh báo mô hình; không ghi đã vá thật.

**Output:** before/after analysis tách biệt; group/action comparison hoặc dữ liệu
before/after do orchestrator giữ; ranking mới và ID phân tích tương ứng S'.

**Chấp nhận khi chọn F02 từ S rỗng:** trước risk41.2825/2 paths; sau risk23.59/1 path;
RI17.6925; path qua APP02 còn tồn tại. Finding F02 không còn trong candidates sau vá.

**Chấp nhận khi chọn F04:** chặn1 path nhưng risk vẫn41.2825, RI0 vì strongest path
qua APP01 còn tồn tại. Giải thích phải nói rõ đặc tính aggregation của model.

**Ngoại lệ:** finding lạ, dữ liệu/config thay đổi giữa hai lần hoặc graph mismatch
thì từ chối so sánh; không ghép hai response khác provenance.

## 4. UC-03 — Dynamic reprioritization và reset

**Mục tiêu:** sau mỗi lựa chọn, đánh giá tác động bổ sung của những finding còn lại.

**Actor:** người phân tích qua SV4. **Input:** cùng snapshot/config, tập S hiện tại.

**Luồng chính:**
1. Xác nhận S đúng snapshot và không có ID trùng/không tồn tại.
2. Dựng graph hiện tại G(S), tính Risk(G(S)).
3. Với từng f chưa vá, thử độc lập từ cùng S; không thay S trong vòng lặp.
4. Tính lại RI(f|S), dense rank và candidate list.
5. SV4 thay kết quả hiện hành bằng kết quả mới, giữ lịch sử có ID nếu cần.
6. Khi reset, caller truyền S=[] và chạy lại; không rollback hoặc sửa database nguồn.

**Chấp nhận sau chọn F01 trong diamond:** không còn path tới DB01; risk0 trong model;
results chỉ còn F02,F03,F04, mỗi finding RI0 và cùng hạng1. Hạng1 là tương đối giữa
ứng viên còn lại, không hàm ý cần vá ngay hoặc mọi tài sản đã an toàn.

**Chấp nhận reset:** snapshot/config ban đầu cho lại risk41.2825 và ranking UC-01.
Business identity tái lập theo hash inputs; thời điểm analysis có thể khác.

**Ngoại lệ:** SV2 lỗi/incomplete khi reanalysis: báo trạng thái chưa cập nhật được;
nếu UI giữ kết quả cũ phải ghi rõ đó là kết quả cũ với S/analysis_id cũ, không trình
bày như kết quả cho trạng thái mới. Không ghi score0 để che lỗi.

## 5. UC-04 — Vá nhóm hoặc cùng vulnerability trên nhiều asset

**Mục tiêu:** đánh giá đúng một hành động gồm nhiều occurrence, tránh cộng trùng RI.

**Actor:** người phân tích; SV4 gọi extension remediation của SV3 sau review.

**Input:** S và danh sách additional_finding_ids; nếu chọn vulnerability_id phải
resolve các occurrence theo scope asset rõ ràng. Không mặc nhiên vá toàn bộ máy
chỉ vì một finding có cùng CVE.

**Luồng chính:** validate scope/IDs → phân tích S → phân tích union S' → lấy risk
và path delta của hai trạng thái → lưu danh sách yêu cầu và tập union thực tế.

**Output:** before/after IDs, risk_before/risk_after, RI nhóm và blocked_path_ids.
Không thay facade AnalysisResult hoặc API public mà chưa review extension.

**Chấp nhận diamond:** RI(F01)=41.2825, RI(F02)=17.6925 riêng lẻ; vá nhóm F01+F02
chỉ giảm41.2825 về0, không giảm58.975. Unknown/duplicate IDs bị từ chối theo hợp đồng.

## 6. UC-05 — Phân tích lại khi dữ liệu hoặc cấu hình thay đổi

**Mục tiêu:** cập nhật quyết định khi finding/topology/criticality hoặc model thay đổi.

**Actor:** SV4/người phân tích, phối hợp SV1/SV2.

**Luồng chính:**
1. SV1/SV2 tạo snapshot mới nếu nội dung dữ liệu thay đổi; không ghi đè snapshot cũ.
2. Nếu đổi weights/model/entry/targets, tạo config phù hợp, lưu đầy đủ version/parameters.
3. Kiểm tra lại tập S; ID không còn tồn tại cần người dùng/caller giải quyết rõ, không
   tự ánh xạ theo tên gần giống hoặc bỏ qua ID.
4. Chạy lại graph/risk/ranking; tạo identity theo đầu vào mới; vô hiệu cache cũ không phù hợp.
5. UI chỉ so sánh số risk như cùng thang khi model/target set/semantics tương thích;
   nếu không phải công bố khác phạm vi.

**Chấp nhận:** thay criticality/EPSS/topology có thể đổi risk/ranking; ID và hash cập
nhật đúng. Không bắt buộc mọi thay đổi đều đảo hạng. Kết quả cũ vẫn truy vết được.

## 7. UC-06 — Dữ liệu thiếu, graph rỗng và lỗi tích hợp

| Trường hợp | Hành vi mong muốn |
|---|---|
| CVSS/EPSS/KEV hoặc context null trong full model | Báo missing fields; không tự fill0/false |
| ID/config/version sai | Báo lỗi có nghĩa, không gọi kết quả là complete |
| SV2 trả dataset/model/patched/target sai | Reject provenance mismatch |
| search_complete=false | Dừng full ranking bằng IncompletePathSearchError |
| Graph hợp lệ, search complete, không có path tới target | Risk0 trong phạm vi model; giải thích giới hạn, không chứng nhận an toàn |
| Snapshot/config bị mutate | Reject mutation, không dùng kết quả bị ảnh hưởng |
| Bất kỳ dependency không sẵn sàng | Giữ dữ liệu nguồn, hiển thị lỗi, không suy ra score0 |

Nếu người dùng muốn CVSS-only khi full inputs thiếu, đó là phương thức phân tích
riêng có nhãn và policy riêng; không tự đổi model trong cùng một response.
Mapping local core errors sang HTTP do SV4 phối hợp; tài liệu không chứng minh handler đã có.

## 8. UC-07 — Cung cấp facts để SV4 giải thích

**Mục tiêu:** giải thích thứ tự bằng ngôn ngữ tự nhiên mà giữ nguyên kết quả engine.

**Input:** analysis + details cùng analysis_id; GraphResult đúng snapshot/config/S.
Metadata asset/service/rule lấy từ dataset có provenance; mô tả vulnerability thật
chỉ lấy từ nguồn đã cung cấp. DEMO IDs không tự biến thành CVE thật.

**Luồng:** SV4 validate ID/hash/scope → dựng ExplanationRequest hiện hành từ analysis
và graph → prompt builder dùng details/context sidecar như facts → kiểm output
ID/số/tie/assumptions → render hoặc fallback unavailable.

**Chấp nhận:** giải thích F01 là điểm chung hai path; F02 còn nhánh thay thế; F04 có
path impact nhưng RI0. Không sửa thứ hạng, tự sinh CVE/RCE/SQLi, khẳng định đã patch
thật hoặc gọi risk41.2825 là xác suất41.2825%. LLM lỗi không làm mất bảng engine.

Use case này là giao điểm SV3/SV4; SV3 cung cấp facts, SV4 triển khai LLM và kiểm tra câu chữ.

## 9. Truy vết và review

| Checklist ngày 2 | Use cases/nội dung |
|---|---|
| Entry/critical/trust/reachability | THREAT_MODEL.md; preconditions UC-01/UC-06 |
| Internet→Web→App01/App02→DB | THREAT_MODEL.md; UC-01/UC-02 |
| Ranking theo path thay CVSS | UC-01 |
| What-if và dynamic reprioritization | UC-02/UC-03; mở rộng UC-04/UC-05 |

- [ ] Bảo giải thích lại được preconditions, flow và expected results.
- [ ] Huy review graph/path/patch assumptions; Hào review input readiness.
- [ ] Hưng review invocation/errors/UI behavior và LLM provenance.
- [ ] Ghi PR/reviewer và trường hợp còn mở; viết tài liệu chưa tự đánh toàn use case Done.
