"""Enterprise asset inventory and declared topology, separate from analysis engines."""
from uuid import uuid4
from common.schemas import Asset
from sv4_app_llm.storage.repository import get_record, list_records, save_record, update_record
from sv4_app_llm.service import inspect_sv1_dataset, dataset_fingerprint

ASSET_TYPES = {
    "web_server": "Máy chủ web / website", "application_server": "Máy chủ ứng dụng",
    "database_server": "Máy chủ cơ sở dữ liệu", "database": "Cơ sở dữ liệu",
    "server": "Máy chủ khác", "workstation": "Máy trạm / máy tính nhân viên",
    "application": "Ứng dụng / dịch vụ", "network_device": "Thiết bị mạng",
    "cloud_resource": "Tài nguyên đám mây", "storage": "Hệ thống lưu trữ",
    "other": "Tài sản khác",
}


def records_of(kind):
    return [get_record(r['id']) for r in list_records(kind)]


def save_enterprise_asset(name, asset_type, address='', system='', subnet='', vlan='',
                          owner='', purpose='', criticality=None, internet_facing=None,
                          sensitive_data=None, record_id=None):
    if not name.strip():
        raise ValueError('Hãy nhập tên tài sản.')
    if asset_type not in ASSET_TYPES:
        raise ValueError('Loại tài sản không hợp lệ.')
    asset_id = 'ASSET-' + uuid4().hex[:12]
    if record_id:
        old = get_record(record_id)
        if old['kind'] != 'enterprise_asset':
            raise ValueError('Bản ghi không phải tài sản doanh nghiệp.')
        asset_id = old['payload']['asset']['asset_id']
    asset = Asset.model_validate({
        'asset_id': asset_id, 'name': name.strip(), 'asset_type': asset_type,
        'criticality': criticality, 'internet_facing': internet_facing,
        'sensitive_data': sensitive_data,
    }).model_dump(mode='json')
    payload = {'draft_version': 'enterprise-intake-v1', 'asset': asset,
               'context': {key: value.strip() or None for key, value in {
                   'address': address, 'system': system, 'subnet': subnet, 'vlan': vlan,
                   'owner': owner, 'purpose': purpose}.items()},
               'assessment_status': 'not_assessed'}
    # Context is SV4 draft metadata, not extra fields added to the canonical schema.
    if record_id:
        update_record(record_id, 'enterprise_asset', asset['name'], payload)
        return record_id
    return save_record('enterprise_asset', asset['name'], payload)


def save_declared_connection(source, target, allowed, evidence):
    ids = {r['payload']['asset']['asset_id'] for r in records_of('enterprise_asset')}
    if source not in ids | {'INTERNET'} or target not in ids or source == target:
        raise ValueError('Chọn hai đầu kết nối hợp lệ; đích phải là tài sản đã khai báo.')
    if type(allowed) is not bool or not evidence.strip():
        raise ValueError('Cần xác định cho phép/chặn và mô tả nguồn xác nhận kết nối.')
    return save_record('enterprise_connection', source + ' → ' + target, {
        'connection_id': 'CONN-' + uuid4().hex[:12], 'source_asset_id': source,
        'target_asset_id': target, 'target_service_id': None,
        'allowed': allowed, 'evidence': [evidence.strip()],
    })


def load_workspace(workspace_id='manual'):
    if workspace_id == 'manual':
        assets = records_of('enterprise_asset')
        return {'source_label': 'Tài sản doanh nghiệp tự khai báo', 'source': 'manual',
                'dataset': None, 'assets': [r['payload']['asset'] for r in assets],
                'contexts': {r['payload']['asset']['asset_id']: r['payload']['context'] for r in assets},
                'services': [], 'findings': [],
                'connections': [r['payload'] for r in records_of('enterprise_connection')],
                'exploit_rules': [], 'analysis_status': 'not_connected'}
    record = get_record(workspace_id)
    if record['kind'] != 'input_dataset':
        raise ValueError('Không phải dataset đầu vào.')
    dataset = record['payload']['dataset']
    return {'source_label': dataset['dataset_id'], 'source': dataset['source'], 'dataset': dataset,
            'contexts': {}, **{key: dataset[key] for key in
                              ('assets', 'services', 'findings', 'connections', 'exploit_rules')},
            'analysis_status': 'not_connected'}


def store_input_dataset(content=None):
    dataset = inspect_sv1_dataset(content)['dataset']
    digest = dataset_fingerprint(dataset)
    for record in records_of('input_dataset'):
        if record['payload']['dataset_hash'] == digest:
            return record['id']
    return save_record('input_dataset', dataset['dataset_id'], {'dataset': dataset, 'dataset_hash': digest})
