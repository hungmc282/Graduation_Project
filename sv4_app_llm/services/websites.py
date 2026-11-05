"""Website intake and next steps. No invented vulnerability/risk calculations."""
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from sv4_app_llm.storage.repository import get_record, list_records, save_record, update_record
from sv4_app_llm.service import dataset_fingerprint, inspect_sv1_dataset

PURPOSES = ("Giới thiệu thông tin", "Bán hàng", "Quản lý công việc", "Khác / chưa rõ")
IMPACTS = ("Chưa biết", "Ít ảnh hưởng", "Ảnh hưởng một phần công việc", "Gián đoạn hoạt động chính")
STATUSES = ("Chưa xử lý", "Đang xử lý", "Tôi đã xử lý")


def normalize_website_url(address):
    address = address.strip()
    if not address:
        raise ValueError("Hãy nhập địa chỉ website.")
    if "://" not in address:
        address = "https://" + address
    try:
        parts = urlsplit(address)
        port = parts.port
    except ValueError as error:
        raise ValueError("Địa chỉ website không hợp lệ.") from error
    if (parts.scheme not in ("https", "http") or not parts.hostname
            or parts.username is not None or parts.password is not None
            or any(c.isspace() for c in address)):
        raise ValueError("Nhập địa chỉ http/https, không kèm tài khoản hoặc mật khẩu.")
    # Keep only the origin: query/fragment may contain secrets and are not needed here.
    host = parts.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    netloc = host + (f":{port}" if port else "")
    return urlunsplit((parts.scheme, netloc, "", "", ""))


def save_website(name, address, purpose, impact, sensitive_data, platform, website_id=None):
    if not name.strip():
        raise ValueError("Hãy đặt tên dễ nhớ cho website.")
    if purpose not in PURPOSES or impact not in IMPACTS:
        raise ValueError("Lựa chọn không hợp lệ.")
    if sensitive_data is not None and type(sensitive_data) is not bool:
        raise ValueError("Thông tin dữ liệu nhạy cảm không hợp lệ.")
    payload = {
        "intake_version": "website-intake-v1", "name": name.strip(),
        "address": normalize_website_url(address), "purpose": purpose, "impact": impact,
        "sensitive_data": sensitive_data, "platform": platform.strip() or None,
        "assessment_status": "not_assessed",
        # Business answers remain draft context until SV1 confirms a mapping.
        "asset_draft": {"asset_id": "WEB-" + uuid4().hex[:12], "name": name.strip(),
                        "asset_type": "website", "internet_facing": None,
                        "criticality": None, "sensitive_data": sensitive_data},
    }
    if website_id:
        old = get_website(website_id)
        payload["asset_draft"]["asset_id"] = old["payload"]["asset_draft"]["asset_id"]
        if old["payload"]["address"] != payload["address"]:
            raise ValueError("Địa chỉ đã thay đổi. Hãy thêm website mới để không trộn báo cáo cũ.")
        update_record(website_id, "website", payload["name"], payload)
        return website_id
    for record in list_records("website"):
        if get_website(record["id"])["payload"]["address"] == payload["address"]:
            raise ValueError("Website này đã được lưu. Chọn website đó để chỉnh sửa.")
    return save_record("website", payload["name"], payload)


def get_website(website_id):
    record = get_record(website_id)
    if record["kind"] != "website":
        raise ValueError("Bản ghi không phải website.")
    return record


def website_evidence(website_id):
    get_website(website_id)
    return [get_record(r["id"]) for r in list_records("website_evidence")
            if get_record(r["id"])["payload"]["website_id"] == website_id]


def attach_website_dataset(website_id, content, asset_id, confirmed):
    website = get_website(website_id)
    if confirmed is not True:
        raise ValueError("Cần xác nhận báo cáo thuộc website này.")
    dataset = inspect_sv1_dataset(content)["dataset"]
    if asset_id not in {a["asset_id"] for a in dataset["assets"]}:
        raise ValueError("Tài sản được chọn không có trong báo cáo.")
    return save_record("website_evidence", "Báo cáo đầu vào · " + website["title"], {
        "website_id": website_id, "website_address": website["payload"]["address"],
        "asset_id": asset_id, "dataset": dataset, "dataset_hash": dataset_fingerprint(dataset),
        "association": "user_confirmed_not_independently_verified",
    })


def preparation_steps(website_id):
    website = get_website(website_id)["payload"]
    evidence = website_evidence(website_id)
    steps = []
    if website["impact"] == "Chưa biết" or website["sensitive_data"] is None:
        steps.append({"id": "context", "title": "Bổ sung thông tin về mức ảnh hưởng",
                      "why": "Cần hiểu website quan trọng thế nào với công việc của bạn.",
                      "action": "Trao đổi với người phụ trách để xác nhận ảnh hưởng và loại dữ liệu lưu trữ."})
    if not evidence:
        steps.append({"id": "evidence", "title": "Chuẩn bị báo cáo kiểm tra website",
                      "why": "Địa chỉ website chưa cho biết website có lỗ hổng nào.",
                      "action": "Nhờ người quản trị cung cấp báo cáo đúng định dạng được hỗ trợ; "
                                "ứng dụng hiện chưa tự quét website."})
    steps.append({"id": "analysis", "title": "Chờ phân tích đường tấn công và mức ưu tiên",
                  "why": "Bộ xử lý phân tích chưa được kết nối, chưa có thứ hạng vá cho website này.",
                  "action": "Bạn có thể xem dữ liệu đã nhập và hỏi AI giải thích; "
                            "kết quả phân tích sẽ được bổ sung khi SV2–SV3 được tích hợp."})
    return steps


def set_action_status(website_id, action_id, status, note=""):
    if action_id not in ("context", "evidence") or status not in STATUSES:
        raise ValueError("Trạng thái hoặc công việc không hợp lệ.")
    get_website(website_id)
    return save_record("website_action", "Tiến độ chuẩn bị dữ liệu", {
        "website_id": website_id, "action_id": action_id, "status": status,
        "note": note.strip(), "verification": "not_verified",
    })


def action_status(website_id, action_id):
    for record in list_records("website_action"):
        item = get_record(record["id"])["payload"]
        if item["website_id"] == website_id and item["action_id"] == action_id:
            return item
    return {"status": STATUSES[0], "note": "", "verification": "not_verified"}


def website_summary(website_id):
    website = get_website(website_id)["payload"]
    lines = ["# Thông tin gửi người hỗ trợ kỹ thuật", "", "Website: " + website["name"],
             "Địa chỉ: " + website["address"], "Mục đích: " + website["purpose"],
             "Ảnh hưởng khi gián đoạn: " + website["impact"],
             "Nền tảng: " + (website["platform"] or "Chưa biết"),
             "", "Chưa có kết quả đánh giá rủi ro hoặc xác nhận bản vá.",
             "Cần báo cáo dịch vụ/lỗ hổng/kết nối và điều kiện khai thác để phân tích."]
    for step in preparation_steps(website_id):
        lines += ["", step["title"], step["action"]]
    return "\n".join(lines)
