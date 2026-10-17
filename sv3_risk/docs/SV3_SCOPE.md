# SV3 Scope & Responsibilities

| Thuộc tính | Giá trị |
|---|---|
| Người phụ trách | Trần Gia Bảo — SV3 |
| Subsystem | Risk & Prioritization Engine |
| Phiên bản tài liệu | 1.0.0 |
| Ngày soạn | 2026-10-18 |
| Trạng thái | Bản thiết kế để nhóm review; chưa ghi nhận phê duyệt |
| Checklist | Tuần 1 — Ngày 1 |
| Hợp đồng liên quan | Chuẩn hóa tài liệu toàn dự án v2; canonical schema 1.0.0 |

## 1. Căn cứ và mục tiêu

Căn cứ mô tả đề tài ngày 07/10/2026, đặc biệt mục 2, 4.4–4.5, 8, 10–12 và 14;
`ARCHITECTURE.md`, `CONTRIBUTING.md` của Graduation_Project; bộ chuẩn hóa v2;
model nghiên cứu `context-path-v1` hiện có trong gói SV3.

SV3 hỗ trợ trả lời: với cùng dữ liệu tài sản, lỗ hổng và đường tấn công, hành động
khắc phục nào làm giảm rủi ro tới tập tài sản quan trọng được chọn nhiều nhất theo
mô hình đã công bố? Quyết định phải có công thức, đầu vào, phiên bản và bằng chứng
có thể tái lập, không phụ thuộc nhận định tự sinh của LLM.

## 2. Phạm vi chịu trách nhiệm

| Mảng | Công việc SV3 | Sản phẩm |
|---|---|---|
| Risk Scoring | Chuẩn hóa CVSS/EPSS/KEV/exposure/asset context; công bố công thức, weights và missing policy | Model spec và code tính risk |
| Risk Propagation | Tính chỉ số trên node/path/target từ các đường khả thi SV2 cung cấp | Path steps, target/system risk |
| Attack-Path Importance | Đánh giá độ bao phủ đường và vị trí choke point theo model | Importance và giải thích giới hạn |
| Remediation Impact | So risk trước/sau từng hành động và tập hành động | RI, risk_after, paths bị loại |
| Dynamic Prioritization | Tính lại marginal impact sau tập vá; xử lý ties và thay đổi snapshot/config | Ranking có phiên bản |
| Baseline/Evaluation | CVSS-only, EPSS-only, CVSS+KEV, weighted-no-graph; ablation/sensitivity và metrics | Raw results, phân tích, báo cáo |

Đếm path trong `blocked-paths-v1` chỉ là demo hồi quy. Không dùng riêng phép đếm
này để nhận hoàn thành Risk Scoring hoặc Risk Propagation của đề tài.

## 3. Ranh giới với các thành viên

| Thành viên | Cung cấp/chịu trách nhiệm | SV3 phối hợp |
|---|---|---|
| Hào — SV1 | Scanner integration, inventory, normalization, enrichment, provenance | Chốt trường cần cho risk; kiểm readiness/missing |
| Huy — SV2 | Reachability, conditions, graph/rules, path search, simulation trạng thái vá | Gọi facade SV2; xác minh provenance/path completeness |
| Bảo — SV3 | Công thức risk, propagation, importance, RI, ranking, baseline/evaluation | Cung cấp kết quả xác định và facts giải thích |
| Hưng — SV4 | API/UI/orchestration, alerts/reporting, LLM, deployment và E2E | Chốt response/errors/sidecars; test cách hiển thị |

SV3 không viết lại scanner/enrichment, không suy diễn exploit edge trong risk code,
không mutate graph của Huy, không tính risk bằng prompt, không làm thay dashboard
hoặc tự triển khai bản vá. SV3 có thể viết dependency tham chiếu cho kiểm thử riêng,
nhưng phải ghi rõ và không thay thế module của người khác khi nghiệm thu.

## 4. Đầu vào

| Input | Nguồn | Điều kiện |
|---|---|---|
| `DatasetSnapshot` | SV1, phối hợp topology/rules SV2 | Đúng shared schema, bất biến, có ID/source/time và references hợp lệ |
| `patched_finding_ids` | Caller SV4/người phân tích | Danh sách occurrence đã mô phỏng vá, không trùng, đều thuộc snapshot |
| `GraphConfig` | Caller theo model SV2 | Model version, entries, targets, max_depth/max_paths rõ |
| `RiskConfig` | Caller theo model SV3 | Model/metric/parameters hỗ trợ, không tự bỏ qua tham số lạ |
| `GraphResult` | SV2 qua `build_graph` | Đúng dataset/version/entries/targets/patched state, path ID ổn định |

Với `context-path-v1`, các giá trị S/E/K/X/A/C phải có dữ liệu theo strict policy.
`null` không phải 0/false. Nguồn synthetic được phép cho lab nhưng phải có nhãn;
không trình bày EPSS/KEV giả lập như dữ liệu threat intelligence thật.

Metadata subnet/VLAN/exploit sources được lưu theo hợp đồng sidecar của nhóm;
SV3 không tự thêm trường vào `common.schemas` strict hoặc tuyên bố dùng một metadata
trong score khi thuật toán chưa đọc trường đó.

## 5. Đầu ra

Facade công khai trong `sv3_risk/service.py`:

```python
analyze(
    dataset: DatasetSnapshot,
    patched_finding_ids: list[str],
    graph_config: GraphConfig,
    risk_config: RiskConfig,
) -> AnalysisResult
```

`AnalysisResult` gồm ID/time/provenance, versions/config_hash, tập vá/targets,
ranking metric/status, risk_before, baseline_cvss_order, results và warnings.
Mỗi item có finding/asset/CVSS, paths before/after/blocked, blocked_path_ids,
risk_after, RI, priority_rank và reason_codes.

`analyze_detailed` hiện là extension trong `sv3_risk.research.service`, trả analysis
và details sidecar: components, path/node/target risk, importance, parameters,
baselines, assumptions và hashes. Không âm thầm đổi response của facade cũ.

Người nhận chính là SV4. SV2 nhận phản hồi về graph/provenance sai; SV1 nhận danh
sách trường thiếu/không hợp lệ để sửa dữ liệu. Không coi local exceptions đã có
HTTP mapping; việc thống nhất `common.errors` cần SV4 phối hợp.

## 6. Quy tắc kỹ thuật cần giữ

- Cùng input/model/config cho cùng business result; timestamp analysis có thể khác.
- Mỗi phương án vá bắt đầu từ cùng tập S, không cộng dồn trong vòng xếp hạng.
- Vá nhóm là phép phân tích lại union, không cộng RI độc lập của từng finding.
- Finding đã vá không còn trong candidates. Tie không tự bị phá bằng CVSS.
- Search incomplete phải báo lỗi theo model hiện hành, không trả ranking chính xác giả.
- Giữ dataset/config gốc; phát hiện upstream mutation hoặc provenance mismatch.
- LLM chỉ diễn giải kết quả; facts strings là dữ liệu không tin cậy, không instruction.

## 7. Phân biệt lựa chọn nghiên cứu với yêu cầu đề tài

PDF yêu cầu risk/path/propagation/RI và baseline comparison, không ấn định weights
`.35/.35/.20/.10`, max-product hoặc tên `context-path-v1`. Đây là lựa chọn model v1
cần giải thích, sensitivity và đánh giá. Điểm heuristic không là xác suất tấn công.
Không có bảo đảm greedy ranking tìm được tập vá tối ưu toàn cục.

## 8. Trạng thái và tiêu chí hoàn thành

Bằng chứng đã có: người dùng chạy gói SV3 trên Windows/Python 3.11.9, 72 test pass,
3 reference scenarios, 112 bản ghi Top-k và benchmark. Chưa chứng minh scanner/
enrichment thật, service SV2 của nhóm, UI/LLM hoặc expert review đã tích hợp.

Để nghiệm thu phần SV3 cuối kỳ cần model spec; code được review; oracle/unit tests;
tích hợp dữ liệu/graph thật; đủ 4 baseline và thực nghiệm; báo cáo limits; các artifact
version/hash để tái lập. Ngày 1 chỉ chốt phạm vi, không yêu cầu toàn subsystem Done.

## 9. Checklist review ngày 1

- [ ] Bảo đọc và giải thích lại mục tiêu cùng ranh giới SV3.
- [ ] Hào/Huy/Hưng xác nhận trách nhiệm và hợp đồng đầu vào/đầu ra liên quan.
- [ ] Đối chiếu tên/kiểu với shared schema thực tế trong repo trước merge.
- [ ] Ghi reviewer, commit/PR và các điểm chưa thống nhất; chưa tự ghi đã approved.
