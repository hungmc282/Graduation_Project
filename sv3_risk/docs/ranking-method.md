> Tài liệu lịch sử cho blocked-paths-v1. Model đầy đủ hiện tại: RISK_MODEL_V1.md. Không dùng file này làm đặc tả duy nhất của subsystem SV3.

# Phương pháp SV3 tuần 1 — blocked-paths-v1

## Phạm vi
Baseline CVSS và marginal critical paths blocked. Chưa có Risk Score/propagation/RI.
Hợp đồng chung: ARCHITECTURE.md 1.0.0; model dùng chung từ common.schemas.

## Thuật toán
S là tập finding đã vá. Tính graph G(S), sau đó thử từng f chưa vá trên G(S hợp {f}).
blocked_path_ids = IDs(P(S)) trừ IDs(P(S hợp {f})); paths_blocked bằng số phần tử tập này.
Mọi ứng viên bắt đầu cùng S; không cộng dồn trong vòng lặp, không cộng tác động độc lập
để suy tác động vá nhóm. Path còn tồn tại phải giữ nguyên cả ID và nội dung.

Dense rank theo paths_blocked giảm dần: 1,1,0 thành hạng 1,1,2. finding_id chỉ sắp hiển thị.
CVSS baseline độc lập: giảm điểm, null cuối; bằng điểm sắp ID để ổn định, không tạo tie-break nghiệp vụ.
Finding đã vá bị loại khỏi cả results và baseline.

## Mô hình và cấu hình
blocked-paths-v1 chỉ nhận ranking_metric=critical_paths_blocked, parameters={}.
Chỉ hỗ trợ demo-graph-v1 có semantics chỉ loại bước khi vá; version khác bị từ chối.
GraphConfig giữ source, targets, max_depth và max_paths được truyền cho SV2.
Tập entry/target không rỗng, không trùng và tham chiếu đúng snapshot.

## Incomplete và lỗi
Quyết định tuần 1: nếu bất kỳ lời gọi SV2 nào search_complete=false, raise
IncompletePathSearchError và KHÔNG trả ranking gần đúng. Tránh dùng hiệu hai phép
đếm path bị cắt làm impact chính xác. Đây là lựa chọn fail-closed cần nhóm review,
thay cho đề xuất cũ trả rank=null; chưa hiện thực hợp đồng approximate ranking.
Caller/UI cần hiển thị thông báo và tăng budget hoặc thu nhỏ scenario có chủ đích.
Không biến lỗi thành paths=[], score=0 hoặc báo an toàn.

common.errors chưa có trong repo: local RiskContractError(ValueError),
UnsupportedRiskModelError và IncompletePathSearchError nằm ở errors.py. Khi common.errors
được triển khai, thống nhất adapter/mapping lỗi chung với SV4; chưa chứng minh HTTP mapping.

## Bảo toàn và provenance
Facade nhận Pydantic models, revalidate bản sao, gọi SV2 bằng bản sao mới cho mỗi mô phỏng.
Nếu SV2 mutate input sẽ báo lỗi. Kiểm tra dataset/version/entry/target/patched state,
path IDs, thứ tự rule/asset và finding của rule. SV2 vẫn chịu trách nhiệm reachability,
preconditions, search completeness thực và semantics của graph; SV3 không thay engine đó.

## Điểm risk và reason codes
risk_score_status=not_implemented; risk_before/risk_after/remediation_impact=null.
BLOCKS_TARGET_PATH: chặn ít nhất một đường.
NO_ADDITIONAL_PATH_BLOCKED: không chặn thêm đường từ S.
MISSING_CVSS: chưa có CVSS; warning chứa finding ID.
Warnings từ SV2 được giữ; demo mock có nhãn MOCK_SV2.

## Định danh
Canonical JSON sort_keys=True, separators=(",",":"), ensure_ascii=False,
allow_nan=False; UTF-8. config_hash là SHA256 của graph_config/risk_config.
dataset_hash là SHA256 DatasetSnapshot serialize chuẩn.
analysis_id là SHA256 của dataset_hash, config_hash và tập vá đã sort.
created_at của analysis không tham gia ID; timestamp snapshot thuộc nội dung snapshot.
Cùng input cho cùng kết quả nghiệp vụ và ID; created_at phân tích thay đổi theo lần gọi.

## Đáp án synthetic
Chưa vá: CVSS F03,F02,F01; F01/F02 blocked=1 rank=1, F03 blocked=0 rank=2.
Sau F01: F02/F03 blocked=0 rank=1. Vá F01+F02 chỉ mất một đường ban đầu.
Code SV3 không hardcode F01/F02/F03; chỉ mock thử nghiệm chứa kịch bản này.
