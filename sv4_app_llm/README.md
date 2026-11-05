# RiskDesk — Dashboard Tổng quan gọn

## Chạy thử

```bash
cd /Users/hungmc/Graduation_Project/Graduation_Project
# Terminal thứ nhất, nếu Ollama chưa chạy:
ollama serve
# Terminal thứ hai:
sv4_app_llm/.venv/bin/python -m streamlit run sv4_app_llm/app.py
```

Ứng dụng mở tại http://localhost:8501. Nếu Ollama đã mở thì không cần chạy lại
`ollama serve`. Không tải thêm model. Model đang có trên máy: `qwen3.5:35b`.

## Năm mục chính

| Mục | Chức năng |
|---|---|
| Tổng quan | Ba số liệu chính, bảng ưu tiên, nút Thử vá và các đường tới đích |
| Tài sản | Xem snapshot hoặc thêm/sửa hồ sơ thủ công, khai báo kết nối |
| Dữ liệu | Upload/kiểm tra/lưu dataset, xem findings và tải JSON |
| Phân tích | Chọn đích, vá một/nhóm findings, tính lại rủi ro và đường đi |
| Báo cáo | Lưu kết quả, xuất JSON/Markdown, xem lịch sử và dữ liệu cũ |

Chọn dữ liệu ở thanh bên. Mặc định dùng **Mẫu · Một đường tới DB** để thử ngay.
Mẫu là dữ liệu giả lập, không trộn vào hồ sơ của người dùng.
Chọn **Hồ sơ của tôi** để thêm/sửa tài sản. Snapshot đã nhập chỉ đọc; nhập lại phiên
bản mới để thay đổi. Không suy ra an toàn khi thiếu dữ liệu hoặc điều kiện khai thác.

## Thử mô phỏng và AI

1. Chọn Mẫu · Một đường tới DB.
2. Tổng quan hiển thị 4 tài sản, 3 findings và 1 đường tới DB01.
3. Bấm Thử vá ở F01: đường tới DB01 còn 0 trong mô hình. F02 có hiệu quả bằng F01.
4. Vào Phân tích để Bỏ mô phỏng hoặc chọn nhiều findings.
5. Bấm **✦ Hỏi AI**, chọn model trên máy và câu hỏi, rồi bấm **Gọi AI giải thích**.
6. AI đọc đúng dataset, tài sản đích và phương án hiện tại. Đổi phạm vi/model/phương án
sẽ không tiếp tục hiển thị câu trả lời cũ. Chỉ gọi model khi bấm nút.

Lần gọi đầu cần nạp model. Thời gian chờ mặc định 180 giây; nội dung AI cần kiểm tra
lại với bằng chứng. Điểm/thứ hạng do SV3 tính, AI không thay đổi chúng. Dữ liệu quá
lớn được báo lỗi thay vì âm thầm cắt bỏ bằng chứng. Không có câu trả lời mẫu thay AI.

### Giải thích phương án vá trước–sau

Khung AI hiển thị riêng kết quả engine của phương án đã chọn: số đường/rủi ro
trước khi vá và sau khi vá. Không dùng mức giảm **thêm** của các finding còn lại để
kết luận hiệu quả của finding đã vá. Với chain, vá F01 làm 1 → 0 đường và
41,2825 → 0 điểm tới DB01; NO_ADDITIONAL_RISK_REDUCTION của F02/F03 chỉ nói về vá thêm.

Khi đã có phân tích, Ollama chọn các ý từ danh mục bằng chứng do engine tạo.
Ứng dụng kiểm tra ID bằng chứng và hiển thị câu chữ gắn với số liệu đó; văn bản tự do
hoặc ID không hợp lệ bị chặn. Đây là phần diễn giải có kiểm tra bằng chứng, không
phải xác nhận mô hình rủi ro hay giả định lab đúng với thực tế. Giải thích đầu vào
khi chưa phân tích vẫn là nội dung AI cần người dùng đối chiếu.

Biến môi trường tùy chọn: `APP_OLLAMA_MODEL` (mặc định qwen3.5:35b),
`APP_OLLAMA_BASE_URL` (mặc định http://127.0.0.1:11434),
`APP_LLM_TIMEOUT_SECONDS` (mặc định 180), `APP_HISTORY_DB` (SQLite local).
Ứng dụng không tự nạp .env. Chỉ gửi dữ liệu tới Ollama đã cấu hình khi bấm nút.

## Graph trực quan

Graph xuất hiện ngay trên Tổng quan và trong Phân tích. Trong Phân tích có hai chế độ:
Đường tấn công (các bước thuộc đường tới tài sản đích do SV2 trả về) và Kết nối mạng
(các kết nối được khai báo, không tự khẳng định khai thác được).
Nét liền xanh là bước còn trên đường tới đích; nét đứt đỏ là bước bị chặn trực tiếp
bởi finding đã mô phỏng vá; nét đứt xám là bước trước đó có trên đường nhưng hiện
không còn thuộc đường tới đích. Máy ngoài đường vẫn hiển thị, không gọi là an toàn.
Ví dụ vá F01: cạnh Internet → Web bị chặn, các bước phía sau chuyển xám, số đường
còn lại tới DB01 bằng 0. Có nút phóng toàn màn hình trên sơ đồ.

## Code đặt ở đâu?

```text
sv4_app_llm/
├── app.py                 # Điểm mở ứng dụng chính
├── config.py              # Đường dẫn, CSDL
├── service.py             # Luồng tương thích và báo cáo phiên bản trước
├── ui/
│   ├── dashboard.py       # Khung ứng dụng, menu, chọn phạm vi
│   ├── compact_pages.py   # Nội dung năm mục chính
│   ├── assistant.py       # Khung AI mở khi cần
│   ├── theme.py           # Màu sắc, khoảng cách, kiểu chữ
│   ├── workspace.py       # Biểu mẫu tài sản và các trang cũ được tái sử dụng
│   └── legacy/            # Dữ liệu website/bản nháp cũ
├── services/
│   ├── analysis.py        # Gọi SV1–SV2–SV3, tính và mô phỏng thật
│   ├── assistant.py       # Ngữ cảnh/câu hỏi AI gắn với đúng kết quả
│   ├── assistant_facts.py # Bằng chứng trước/sau và kiểm tra nội dung hiển thị
│   ├── enterprise.py      # Hồ sơ và snapshot người dùng
│   └── websites.py        # Hồ sơ website cũ
├── llm/                   # Kết nối Ollama, prompt dữ liệu và báo cáo
├── adapters/              # Bộ nối SV1
├── storage/               # SQLite; giữ nguyên dữ liệu cũ
├── reports/               # Xuất JSON/Markdown
├── demos/                 # Đọc báo cáo mẫu cũ
├── apps/risk_analysis/    # Màn hình mô phỏng độc lập trước đây, vẫn chạy được
└── tests/                 # Kiểm thử nghiệp vụ cũ
```

SV1, SV2, SV3 vẫn ở các thư mục riêng. Không chuyển công thức rủi ro vào UI/prompt.
Phần `service.run_analysis(mode="integrated")` cũ vẫn là giao diện chưa dùng;
ứng dụng mới gọi `services.analysis.analyze_dataset`.
Các phần chờ phát triển không được dựng thành hàng loạt thẻ rỗng trên dashboard.

## Kiểm thử

```bash
sv4_app_llm/.venv/bin/python -B -m pytest -q
```

Test mặc định dùng AI mock, không gọi mạng/model thật. Đã kiểm tra riêng một câu hỏi
thực tế với qwen3.5:35b trên Ollama local. SQLite của người dùng không bị thay thế.
Bản sao code trước khi đổi giao diện: `local_data/ui-before-compact.tar.gz`.
