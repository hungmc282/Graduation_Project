# SV3 — Ghi chú ngày 1

## Người phụ trách
Trần Gia Bảo — SV3: Risk & Prioritization.

## Mục tiêu tuần 1
- Xếp hạng finding theo CVSS giảm dần.
- Tính số đường tới DB01 bị chặn khi mô phỏng vá.
- Giữ đồng hạng khi tác động bằng nhau.
- Tính lại tác động sau khi đã vá một finding.
- Bàn giao AnalysisResult cho SV4.

## Môi trường đã kiểm tra
- Git: 2.56.0.windows.2.
- Python: 3.11.9.
- Đã tạo môi trường .venv.

## Dữ liệu cần nhận
- SV1: DatasetSnapshot và dữ liệu synthetic.
- SV2: build_graph(...) trả GraphResult.
- Cả nhóm: common/schemas.py thống nhất.

## Kết quả tính tay kỳ vọng
Ban đầu có 1 đường tới DB01, đi qua F01 và F02.

| Finding | CVSS | Đường bị chặn khi vá riêng | Hạng theo tác động |
|---------|------|---------------------------|-------------------|
| F01     | 7.5  | 1                         | 1                 |
| F02     | 8.0  | 1                         | 1                 |
| F03     | 9.8  | 0                         | 2                 |

- Baseline CVSS: F03 → F02 → F01.
- F01 và F02 đồng hạng theo tác động.
- Sau khi vá F01, vá thêm F02 chặn thêm 0 đường.
- Vá cả F01 và F02 chỉ chặn tổng 1 đường.

## Nguyên tắc triển khai
- Làm việc trong sv3_risk/.
- Gọi facade SV2, không tự sửa graph.
- LLM không tính điểm hoặc thay đổi ranking.
- Chưa có Risk Score thì các trường risk để null.
- Fixture/mock phải ghi rõ, không coi là tích hợp thật.