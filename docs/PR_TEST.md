# [Để nhóm xem và góp ý] Bản tích hợp local trên nhánh test

## Mục đích

Nhánh `test` tập hợp bản đang chạy trên máy SV4 để cả nhóm tải về, kiểm tra và đối chiếu trước khi quyết định ghép vào `main`. Đây là bản thử nghiệm; không tự thay thế nhánh phụ trách của từng người.

Bản này gồm cả phần bổ sung khi làm SV4 và phần ghép từ các module của nhóm, không có nghĩa toàn bộ code ở đây do SV4 viết mới.

Ngày bàn giao: 05/11/2026. Mốc so sánh:

| Nhánh | Mã phiên bản lúc chuẩn bị |
|---|---|
| main và sv1-data | `9f9842b31cd857749a255f3242207d4c9bf38c51` |
| sv2-attack-graph | `8e4660ec43c7f3b8c4ffc97ac6baed8edf046421` |

Danh sách đối chiếu file: [FILES_CHANGED_TEST.md](FILES_CHANGED_TEST.md).

## 1. Phần SV1: đã sửa gì?

Các file có nội dung khác so với `sv1-data` ở mốc trên:

```text
sv1_data/README.md
sv1_data/adapters/nmap_xml.py
sv1_data/adapters/trivy_json.py
sv1_data/enrichment/cache.py
sv1_data/enrichment/service.py
sv1_data/pipeline.py
```

- Kiểm tra kỹ hơn đầu vào Nmap/Trivy, gồm cấu trúc báo cáo và cổng mạng.
- Khi các kết quả cùng mã nhưng khác thông tin, báo xung đột thay vì âm thầm chọn bản đầu.
- Kiểm tra Trivy cùng finding ID nhưng khác image/target.
- Thêm chế độ offline để dùng EPSS/KEV đã chuẩn bị trên máy mà không thử mạng.
- Thống kê các bản ghi trùng khi ghép dữ liệu.

Trivy đã có trên GitHub; bản này chỉnh thêm adapter, không phải thêm scanner đó từ đầu.

Các phần mới liên quan SV1:

```text
sv1_data/merging.py
sv1_data/demo.py
tests/sv1_data/test_sv1_input_merge.py
tests/sv1_data/test_sv1_milestone1.py
data/samples/sv1_input_checks/
data/samples/sv1_milestone1/
docs/sv1/
```

Chúng phục vụ ghép dữ liệu nhất quán, thử đầu vào sai và demo hai lần nhập có đối chiếu đáp án. Demo dùng dữ liệu giả lập, chưa thay thế kiểm chứng scanner thật.

**Nhờ SV1:** đọc thay đổi, chạy test/demo, báo phần nào muốn giữ hoặc cần chỉnh. Sau khi tiếp nhận mới chia lại việc còn thiếu, tránh viết lại phần đã có. Các việc cache/feed hỏng, trạng thái ghi khi DB lỗi, dataset ID khi gọi enrich_dataset riêng và history thay đổi exploit rules vẫn cần rà soát/sửa; bản test chưa tuyên bố hoàn tất các lỗi đó.

## 2. Phần SV2 và dữ liệu dùng chung

So với nhánh `sv2-attack-graph` ở mốc đã ghi, thay đổi tập trung ở:

```text
common/schemas.py
sv2_attack_graph/graph_models.py
```

`GraphConfig`, `AttackPath`, `GraphResult` được đưa về `common/schemas.py` để các module dùng cùng một kiểu dữ liệu. `graph_models.py` vẫn cho phép lấy các kiểu này từ đường dẫn cũ để code hiện tại tiếp tục gọi được. Bổ sung các kiểu kết quả/cấu hình cho phần rủi ro trong schema chung.

Không có khác biệt nội dung ở thuật toán `sv2_attack_graph/service.py` so với mốc nhánh SV2 nêu trên.

**Nhờ SV2:** xác nhận kiểu dữ liệu, đầu vào/đầu ra, chạy lại test graph và kiểm kịch bản sau vá. Chưa tự đổi tên/ý nghĩa trường chung khi chưa báo các bên dùng dữ liệu.

## 3. Phần SV3 được ghép vào bản chạy chung

Bổ sung phần tính rủi ro, ưu tiên, mô phỏng vá, kịch bản chain/diamond/multi-target, kiểm thử và tài liệu trong `sv3_risk/` so với `main` được đối chiếu.

**Nhờ SV3:** đối chiếu với nhánh đang làm; xác nhận công thức, kết quả mong đợi, đồng hạng và giới hạn mô hình. Không coi bản này tự động thay thế bản chính thức của SV3.

## 4. Phần SV4 đã bổ sung

- Màn hình tổng quan, tài sản, dữ liệu, phân tích và báo cáo.
- Nhập snapshot qua bộ kiểm tra SV1, gọi graph/risk thật và hiển thị kết quả.
- Chọn một/nhóm finding để mô phỏng vá, xem đường đi và rủi ro thay đổi.
- Kết nối Ollama để giải thích theo đúng dữ liệu đang xem; AI không sửa điểm/thứ hạng.
- Lưu lịch sử SQLite, xuất JSON/Markdown.
- Kiểm thử phần nối các module và một số thao tác giao diện.

SV4 tiếp tục phụ trách giao diện, luồng sử dụng, API, báo cáo và triển khai. API, PDF/CSV, đóng gói Docker và nghiệm thu lab thật chưa hoàn tất.

## 5. Cấu hình và tài liệu

Thêm `pyproject.toml`, `uv.lock`, `.streamlit/config.toml`, dữ liệu demo và test tích hợp. README gốc có bổ sung cách chạy nhưng vẫn còn đường dẫn máy SV4 ở một số ví dụ; khi tải về hãy dùng thư mục của máy mình theo hướng dẫn dưới đây.

File môi trường ảo, lịch sử cá nhân, cache và dữ liệu chạy bị ignore không thuộc bản bàn giao. Không cần sao chép thư mục `.venv` của SV4.

## 6. Cách tải và chạy thử

Nếu chưa có repo, tạo bản riêng:

```bash
git clone --branch test https://github.com/hungmc282/Graduation_Project.git Graduation_Project_test
cd Graduation_Project_test
uv sync --locked
uv run pytest -q
uv run python -m sv1_data.demo
uv run streamlit run sv4_app_llm/app.py
```

Nếu đang có code làm dở, nên dùng bản clone riêng ở trên để tránh ảnh hưởng công việc hiện tại. Nếu đã làm việc trên nhánh test và thư mục sạch, cập nhật bằng `git pull --ff-only origin test`.

Muốn đối chiếu bằng Git:

```bash
git fetch origin
git diff origin/sv1-data...origin/test -- sv1_data tests/sv1_data
git diff origin/sv2-attack-graph origin/test -- sv2_attack_graph common/schemas.py
```

Lệnh SV1 dùng điểm chung giữa các nhánh; lệnh SV2 đối chiếu trực tiếp hai bản. Mốc chính xác ban đầu đã ghi ở đầu tài liệu; nếu các nhánh tiếp tục thay đổi thì kết quả đối chiếu theo tên nhánh cũng đổi.

AI cần Ollama và model đã cài riêng. Không cần chạy AI để kiểm tra graph/risk và demo SV1. Chi tiết biến cấu hình xem `sv4_app_llm/README.md`; không để model lớn hoặc mật khẩu vào repo.

## 7. Kết quả kiểm tra và giới hạn

- 347 bài kiểm thử SV1 đạt trên bản local đã đối chiếu.
- Toàn dự án có 494 bài và 6 kiểm tra con đạt trên bản kiểm tra trước khi bàn giao.
- Demo SV1 hai lần nhập offline đạt đáp án.
- Môi trường kiểm tra: Python 3.14. Chưa chứng nhận Python 3.11, PostgreSQL thật, Docker hoặc toàn luồng scanner thật.
- Lint phần SV1/schema chung đạt; còn một số file chưa thống nhất định dạng.
- Các báo cáo/kịch bản mẫu là synthetic, không phải bằng chứng hệ thống thật an toàn hoặc đã được vá.

Kết quả chạy lại trên nhánh bàn giao được lưu tại [TEST_RESULTS_TEST.md](TEST_RESULTS_TEST.md).

## 8. Cách thống nhất việc tiếp theo

1. Mỗi người tải nhánh test về và xem phần mình phụ trách.
2. Ghi rõ phần đồng ý giữ, phần trùng với nhánh mình và phần muốn chỉnh.
3. Chia các thay đổi được đồng ý thành PR nhỏ theo module, có người nhận duyệt.
4. Chỉ ghép vào main sau khi nhóm thống nhất; mọi người cập nhật cùng mốc rồi tiếp tục.
5. SV1/SV2/SV3 tiếp tục quản lý module tương ứng; SV4 sửa phần tích hợp. File chung cần phối hợp trước.

Mục tiêu là cùng nhìn một bản chạy được, giữ lại công sức đã có và tránh sửa hai phiên bản song song.
