# Quy tắc làm việc nhóm

## 1. Quyền sở hữu

- SV1: `sv1_data/`, nhánh `sv1-data`.
- SV2: `sv2_attack_graph/`, nhánh `sv2-attack-graph`.
- SV3: `sv3_risk/`, nhánh `sv3-risk`.
- SV4: `sv4_app_llm/`, nhánh `sv4-app-llm`.
- File ở thư mục gốc do một người điều phối cập nhật sau khi nhóm thống nhất. Không đồng thời sửa README, cấu hình hoặc danh sách thư viện chung.
- Mỗi người tự tạo cấu trúc con khi cần. Thống nhất mã tài sản, finding và đầu vào/đầu ra trước khi viết phần tích hợp.

## 2. Quy tắc bảo vệ main

Bộ khung ban đầu được đưa vào main một lần để tất cả nhánh có cùng điểm xuất phát. Sau đó:

1. Không lập trình hoặc push trực tiếp vào main.
2. Mọi thay đổi vào main phải qua Pull Request (PR).
3. Có ít nhất một thành viên khác đọc và duyệt; sửa lỗi trước khi merge.
4. Người điều phối kiểm tra trên bản ghép: chức năng thay đổi chạy được, dữ liệu mẫu hợp lệ, phần đã tích hợp không hỏng.
5. Nếu chưa chạy toàn ứng dụng, ghi rõ giới hạn; không mô tả phần chưa chạy là đã kiểm chứng.
6. Không force push vào main hoặc nhánh phụ trách. Không dùng `git reset --hard` để giải quyết conflict.

Đây là quy tắc của nhóm, chưa tự tạo bảo vệ trên GitHub. Chủ repo cần vào Settings → Rules → Rulesets (hoặc Branches tùy giao diện), áp dụng cho main: yêu cầu PR, ít nhất 1 approval, giải quyết các thảo luận trước merge, chặn force push và xóa nhánh. Chỉ bắt buộc kiểm tra tự động khi nhóm đã có CI thực sự chạy. Khả năng áp dụng phụ thuộc gói tài khoản/repo; không bật quy tắc bắt buộc approval nếu chưa có reviewer đủ quyền.

## 3. Bắt đầu trên máy mỗi người

Ví dụ SV1 (những người khác thay tên nhánh):

```bash
git clone https://github.com/hungmc282/Graduation_Project.git
cd Graduation_Project
git fetch origin
git switch --track origin/sv1-data
```

Nếu đã có nhánh local, dùng `git switch sv1-data` thay lệnh tạo nhánh theo dõi.

## 4. Trước mỗi buổi làm việc

```bash
git status
git switch sv1-data
git fetch origin
git pull --ff-only origin sv1-data
git merge origin/main
```

Chỉ đổi nhánh/cập nhật khi thay đổi hiện tại đã được commit hoặc cất an toàn. Nếu `pull --ff-only` không thực hiện được, dừng và nhờ người điều phối xem lịch sử; không force push. Merge main vào nhánh phụ trách để nhận phần đã được ghép của cả nhóm.

## 5. Gửi kết quả

Kiểm tra `git diff` và bảo đảm không có dữ liệu nhạy cảm, môi trường Python hoặc model AI.

```bash
git add sv1_data/
git commit -m "feat(data): add sample loader and validation"
git push origin sv1-data
```

Trên GitHub tạo PR với base là main, compare là nhánh phụ trách. PR ghi:

- Thay đổi gì và ai dùng đầu ra này?
- Chạy bằng cách nào?
- Đã kiểm tra trên dữ liệu nào, kết quả kỳ vọng là gì?
- Có thay đổi cấu trúc dữ liệu, thư viện hoặc ảnh hưởng module khác không?
- Lỗi/giới hạn còn lại.

Mỗi PR nên chứa một công việc nhỏ có thể kiểm tra. Việc chưa hoàn thành dùng Draft PR.

## 6. Sau khi PR được ghép

- Dùng merge commit (Create a merge commit) cho PR từ bốn nhánh phụ trách lâu dài; không squash/rebase các PR này để tránh lặp lại lịch sử ở lần sau.
- Không xóa bốn nhánh phụ trách sau merge. Nếu bật tự xóa nhánh trên repo, tắt hoặc khôi phục nhánh phụ trách trước khi tiếp tục.
- Quay lại nhánh phụ trách và chạy quy trình cập nhật ở mục 4 trước khi làm việc tiếp.
- Nếu sau này dùng nhánh con ngắn hạn, thống nhất riêng nơi ghép và cách xóa; bộ khung không tạo sẵn các nhánh đó.

## 7. Tránh và xử lý conflict

- Không sửa cùng file cùng lúc; báo nhóm trước khi sửa file chung hoặc phần người khác.
- Không đổi tên/di chuyển thư mục module khác khi chưa thống nhất.
- Thay đổi hợp đồng dữ liệu phải thông báo người nhận và cập nhật ví dụ tương ứng trong cùng PR.
- Cập nhật main thường xuyên; commit nhỏ, mô tả rõ, tránh commit toàn repo khi chỉ sửa một module.
- Nếu conflict: xem `git status`, phối hợp chủ file, sửa từng phần, chạy lại kiểm tra rồi commit. Không chọn toàn bộ ours/theirs nếu chưa hiểu thay đổi bị bỏ.
- Nếu chưa chắc, dùng `git merge --abort` để hủy lần merge khi có thể, rồi nhờ người điều phối. Không xóa file để làm mất conflict.

## 8. Dữ liệu và kiểm chứng

- Chỉ đưa dữ liệu giả lập hoặc dữ liệu được phép chia sẻ lên GitHub; ghi rõ nguồn synthetic.
- Không commit token, mật khẩu, `.env`, dữ liệu scan nhạy cảm, model Ollama hoặc file trọng số. Nếu lộ secret, thu hồi/đổi secret ngay; xóa file ở commit mới chưa loại khỏi lịch sử.
- Khi phát hiện main hỏng: báo nhóm, dừng ghép thêm, sửa qua PR hoặc revert PR gây lỗi qua PR; không reset/force push main.
- LLM không được sửa điểm, thứ tự ưu tiên hay kết quả mô phỏng. Chức năng ứng dụng cốt lõi cần hiển thị được khi LLM không chạy.
