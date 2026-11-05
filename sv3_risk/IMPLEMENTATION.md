# SV3 — Tích hợp bản context-path-v1

## Hiện thực
- service.analyze dispatch blocked-paths-v1 (hồi quy demo cũ) hoặc context-path-v1.
- research.engine: local risk, propagation, path importance, 4 baselines.
- research.service.analyze_detailed: AnalysisResult chuẩn và details sidecar.
- research.remediation: scope CVE/finding và tính lại vá nhóm.
- research.cli/evaluate/benchmark: chạy scenario, Top-k/ablation/sensitivity và đo lặp.

Đọc ../START_HERE.md trong gói bàn giao để chạy một lệnh trên Windows.
Bản này thay hướng dẫn chạy 29-test và mock-only trước đây. Còn giữ tests cũ để hồi quy.

## Facade cho SV4
```python
from sv3_risk.service import analyze

analysis = analyze(dataset, patched_finding_ids, graph_config, risk_config)
```
Đầu vào là shared Pydantic models từ common.schemas. RiskConfig cho bản mới:
model_version=context-path-v1, ranking_metric=remediation_impact, parameters={}
để dùng defaults đã công bố. analyze_detailed cùng tham số khi cần components/baselines.

## Phụ thuộc SV2
Gọi build_graph(dataset, patched_finding_ids, config) -> GraphResult qua facade.
Không import private của SV2. Model graph phải chỉ loại bước khi vá và trả paths đầy đủ;
SV3 validate provenance, IDs, state hiện tại, cấu trúc path và phát hiện mutation.
SV2 vẫn chịu trách nhiệm semantics và mức bao phủ exploit/reachability thực tế.

## Reference lab
reference_lab/ chứa shared schema đề xuất và graph enumerator theo rule synthetic.
Runner chọn nó bằng PYTHONPATH chỉ trong subprocess; không thay sys.path trong core.
Đây là code dependency tham chiếu có thực thi (không replay đáp án F01), nhưng không
phải code SV2 đã được Huy nghiệm thu, không scanner hoặc exploit verification.
Không chép reference_lab đè common/ hoặc sv2_attack_graph/ của repo nhóm.

## Mapping lỗi
RiskContractError và subclasses hiện cục bộ vì common.errors chưa có trên bản repo
đã đọc. SV4 cần map sang common.errors/envelope API sau review. IncompletePathSearchError
không được xử lý như score=0/no paths. MissingRiskDataError báo chính xác field thiếu.
Không tự đẩy schema changes khi subsystem khác chưa cập nhật consumer.

## Dependency và source
standalone/requirements.lock.txt chỉ cho môi trường artifact độc lập. Repo nhóm dùng
pyproject/uv.lock; chuyển dependencies qua điều phối và test, không giữ hai nguồn root.
SOURCE_MANIFEST.json ghi hashes source thực; base commit riêng không đồng nghĩa code
đã commit hoặc push. Chưa có GitHub mutation/PR/merge trong tác vụ tạo gói.

## Giới hạn kiểm chứng
Đọc TEST_RESULTS.md và REQUIREMENTS_TRACEABILITY.md. Tests kiểm logic và reference lab
synthetic; chưa tích hợp scanner thật, Huy service thật, UI/API/LLM/PostgreSQL hoặc chuyên gia.
Risk score tính được hoàn chỉnh theo model v1 nhưng model còn phải được nghiên cứu/đánh giá.
