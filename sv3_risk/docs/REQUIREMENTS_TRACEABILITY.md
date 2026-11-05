# Đối chiếu mô tả đề tài và bản bàn giao SV3

Nguồn: Mô tả đề tài 07/10/2026, mục 2, 4, 8–12, 14. Phân biệt đầy đủ code SV3
với hoàn tất toàn hệ thống; không có tỷ lệ % tổng thể vì chưa kiểm chứng các subsystem khác.

| Yêu cầu SV3 | Hiện thực | Bằng chứng |
|---|---|---|
| Scoring S/E/K/X/A/C | research/engine.py | Oracle chain/multi-target, input missing tests |
| Risk propagation node/path | compute_state | Prefix/product/strongest target tests |
| Attack-path importance | RiskState.path_importance | Choke point 1, branch .5 |
| Remediation Impact | research/service.py | Before/after, group non-additivity |
| Dynamic ranking | service và evaluation | All patch subsets, static/dynamic ablation |
| 4 baselines | baselines | Candidate coverage và evaluation CSV |
| Top-k/risk metrics | research/evaluate.py | CSV tái lập, cùng full model làm thước đo |
| Sensitivity/ablation | evaluate | weights variants, no-propagation, no-context |
| Runtime/reanalysis | benchmark.py | 10 runs, warm-up, p50/p95, Python allocation peak |
| Giải thích có căn cứ | details sidecar | Components, path steps, reasons, assumptions |
| Tái lập | configs/hash, fixtures, lock, runner | TEST_RESULTS và SOURCE_MANIFEST |

## Những phần thuộc hệ thống chung, chưa được gói SV3 chứng minh
- Ít nhất 2 nguồn scanner thật; Nmap/topology lab nhiều subnet.
- Ingestion, scan history, CVE/EPSS/KEV/exploit metadata cập nhật từ nguồn thật.
- Graph engine của Huy chạy từ dữ liệu lab thật và validated preconditions.
- PostgreSQL/graph persistence, API/auth/UI/alerts/PDF/CSV báo cáo của platform.
- Docker Compose toàn hệ thống; gói chỉ có Compose chạy lab SV3 độc lập.
- Expert assessment và effectiveness bên ngoài synthetic fixtures.

Reference lab có bộ enumerate graph theo rule được khai báo; không dùng if F01/F02
để trả đáp án. Đây là dependency tham chiếu nằm ngoài thư mục SV2 của repo; không
được ghi đè phần của Huy hoặc gọi là scanner/graph đã xác minh thực tế.

## Các sai lệch cũ đã xử lý
1. Đếm path là demo khởi đầu: giữ blocked-paths-v1 để hồi quy, bổ sung context-path-v1.
2. Thiếu weighted-no-graph baseline: đã thêm cùng ba baseline còn lại.
3. risk=null là đúng cho bản cũ; bản context đầy đủ trả risk thực tính theo công thức.
4. Dataset đơn đường thiếu EPSS/KEV: bổ sung 3 scenario synthetic có services và đủ tín hiệu.
5. Search incomplete: dừng bằng lỗi có nghĩa; không xuất ranking chính xác giả.
6. Hợp đồng lỗi common.errors chưa hiện thực: giữ local exceptions, cần SV4 mapping khi tích hợp.

## Đánh giá cuối
Đã hiện thực lõi SV3 cho model v1 và lab tái lập. Model còn là giả thuyết nghiên cứu;
chưa thể gọi toàn đồ án hoàn thành hoặc chứng minh ưu việt trong môi trường thực.
