# Context-Aware Risk & Prioritization — context-path-v1

Trạng thái: thuật toán nghiên cứu đã hiện thực và kiểm thử trên lab synthetic.
Chưa được hiệu chuẩn/xác nhận bởi chuyên gia hoặc dữ liệu tấn công thực tế.
Mục tiêu: hiện thực trách nhiệm SV3 ở mục 8 bản mô tả đề tài ngày 07/10/2026.

## 1. Đơn vị phân tích và hành động
Finding là một occurrence trên một asset/service. Một hành động vá chọn finding_id.
Vá cùng CVE trên nhiều asset phải truyền toàn bộ finding_id tương ứng; không tự suy
rằng vá một occurrence đã khắc phục tất cả máy. Vá nhóm luôn phân tích lại tập hợp,
không cộng RI đơn lẻ. Entry có thể là INTERNET hoặc một asset đã kiểm soát.
Targets được caller chọn và công bố; Risk(G) là risk tới tập targets này, không
khẳng định bao phủ mọi tài sản hoặc mọi kiểu tấn công trong doanh nghiệp.

## 2. Chuẩn hóa tín hiệu và local risk
Với finding f trên asset a:
- S = cvss_score / 10.
- E = epss_probability, lấy từ snapshot hoặc ghi rõ synthetic.
- K = 1 nếu is_kev=true, 0 nếu false; null không phải false.
- X = 1 nếu asset internet_facing=true, 0 nếu false. Reachability/segmentation
  được quyết định riêng bởi SV2, không suy ra exploit từ cổng mở.
- A = criticality / 5.
- C = 1 nếu sensitive_data=true, 0 nếu false.

Transition index q(f) = .35*S + .35*E + .20*K + .10*X.
Asset loss L(a) = .80*A + .20*C.
Local weighted baseline W(f) = 100*q(f)*L(a).

q và L thuộc [0,1], W thuộc [0,100]. Đây là weighted heuristic, không phải xác suất.
EPSS là một tín hiệu đầu vào; kết hợp EPSS với tín hiệu khác không bảo toàn ý nghĩa
xác suất ban đầu. Toàn bộ weights là tham số nghiên cứu, chưa tối ưu thực nghiệm.

## 3. Risk propagation
SV2 cung cấp các đường khai thác khả thi đầy đủ theo model/config của SV2.
Trên mỗi đường p, khởi tạo strength=1. Mỗi finding khác nhau lần đầu xuất hiện
nhân strength với q(f). Trust step có multiplier=1 theo giả định lab có evidence.
Finding lặp lại không nhân thêm lần nữa. Node strength được ghi là max prefix
strength của các đường tới target đi qua node; không là inventory toàn bộ reachable nodes.

T(p) = tích q(f) trên các finding duy nhất của đường p.
RiskPath(p) = 100*L(target(p))*T(p).
TargetRisk(t) = max RiskPath(p) trong các path tới t; không có path thì bằng 0 trong mô hình.
Risk(G) = tổng TargetRisk(t) / số target đã cấu hình, giữ nguyên mẫu số trước/sau vá.

Không cộng xác suất các đường chồng lặp. Max-product là lựa chọn mô hình hóa
công bố được, không chứng minh các điều kiện khai thác độc lập. Đường dài bị giảm
strength là giả định attenuation; phải kiểm tra độ nhạy và đối chiếu chuyên gia.
Đường trust-only có strength=1, cần audit kỹ giả định quyền truy cập.

## 4. Attack-path importance P
P(f) = trung bình trên targets của L(t) nhân tỷ lệ paths tới t có chứa f.
Nếu t không có path, đóng góp bằng 0. P thuộc [0,1].
P giúp giải thích vị trí choke point và độ bao phủ đường, được ghi trong details.
Không cộng P thêm một lần vào Risk(G): graph/path và propagation đã ảnh hưởng risk;
tránh tự cộng thêm trọng số không có đánh giá. Ưu tiên cuối dựa marginal RI.
Mẫu số path-count có thể thiên lệch theo cách biểu diễn graph; công bố cùng metric
unique critical targets và ablation, không coi P là chuẩn phổ quát.

## 5. Remediation impact và dynamic prioritization
S là tập finding đã vá; mỗi ứng viên f được thử từ cùng S.
RI(f|S) = Risk(G(S)) - Risk(G(S hợp {f})).
Lấy cả số đường bị chặn, blocked_path_ids và risk sau vá từ cùng snapshot/config.
Sắp RI giảm dần, dense rank sau round 9 chữ số thập phân; ID chỉ để hiển thị.
Sau một lựa chọn, cập nhật S và tính lại tất cả RI. Chưa tối ưu chi phí vá hoặc chứng
minh tìm được tập vá tối ưu toàn cục. Greedy theo RI không có bảo đảm tối ưu chung.

Max-product chọn strongest path: loại một path yếu hơn có thể paths_blocked>0
nhưng RI=0 vì strongest path vẫn tồn tại. Đây là đặc tính có chủ đích và giới hạn
của model v1; UI cần hiển thị cả hai metric để người dùng hiểu.

## 6. Bốn baselines bắt buộc
- CVSS-only: giảm dần S, giữ tie.
- EPSS-only: giảm dần E, giữ tie.
- CVSS+KEV: lexicographic (K, CVSS), KEV true trước; là quy tắc baseline đề xuất
  cần nhóm/giảng viên chốt, không gọi là công thức chuẩn bên ngoài.
- Weighted Risk không graph: W(f) ở mục 2, không dùng path/reachability/propagation.

Cùng candidate set, snapshot và budget k. Giá trị null bị từ chối trong chế độ đầy
đủ; không ngầm điền 0. Baseline CVSS tuần 1 vẫn có missing policy riêng.

## 7. Dữ liệu thiếu và tính đầy đủ
readiness(dataset) liệt kê missing. context-path-v1 strict yêu cầu các trường S/E/K/X/A/C
có giá trị cho dataset; không nội suy. Không trả complete nếu thiếu đầu vào hoặc
search_complete=false. IncompletePathSearchError dừng ranking; không dùng hiệu hai
đếm path bị cắt làm RI đầy đủ. risk_score_status=complete chỉ nói tính toán hoàn tất
theo model và đầu vào, không nói threat model đã đúng hoặc dữ liệu đã được xác minh.

## 8. Định danh và output
Giữ public AnalysisResult schema 1.0.0 để không tự phá hợp đồng nhóm. analyze(...)
dispatch theo RiskConfig.model_version. context-path-v1 dùng remediation_impact.
analyze_detailed(...) cung cấp sidecar report gồm components, path steps, target risk,
P, baselines, assumptions và parameters. Sidecar chưa phải schema public thay thế.
config_hash lưu weights đã resolve defaults; analysis_id gồm snapshot hash/config/tập vá.
Graph version thay đổi, weights/dataset thay đổi đều tạo ID mới.

## 9. Kịch bản và đáp án tính tay
Chain: q(F01)=.8425, q(F02)=.49, L(DB)=1.
Risk=100*.8425*.49=41.2825. Vá F01 hoặc F02: risk 0; vá F03: risk giữ nguyên.
Diamond: path phụ có q(F04)=.28; vá F02 còn risk=100*.8425*.28=23.59.
RI(F02)=17.6925; vá F01 chặn cả 2 path. Vá F04 chặn 1 path nhưng RI=0.
Multi-target: thêm target DB02, L=.84, nhánh F03 q=.9755.
Risk=(41.2825+100*.84*.9755)/2. Thứ tự ưu tiên thay đổi theo giá trị/đường tới target.

## 10. Thực nghiệm và giới hạn
Evaluation dùng 4 baselines, proposed dynamic/static và ablation bỏ propagation
(max-local thay product), bỏ target context (loss=1). Tất cả policy được đo bằng
cùng full model Risk(G) để tránh thay thước đo khi so sánh.
RiskReduction@k=(Risk0-Riskk)/Risk0; Risk0=0 trả null/undefined.
Metrics khác: paths removed, critical targets no longer exploitable-reachable,
precision/recall KEV hoặc EPSS>=.5 trong Top-k, thời gian graph/reanalysis và memory.
Top-k tie dùng ID để chọn tái lập; không biến ID thành ưu tiên nghiệp vụ.

Giảm chính Risk(G) do model định nghĩa không tự chứng minh ưu tiên thực tế đúng.
Cần lab nhiều subnet, scanner/enrichment thật, expert assessment, nhiều topology lớn
và đánh giá ngoài tập thiết kế. Hiện không có kết quả kiểm chứng thực địa hay chuyên gia.
