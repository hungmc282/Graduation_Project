from pathlib import Path
import pytest
from common.errors import ContractError, InvalidReferenceError, UnsupportedVersionError
from sv2_attack_graph.graph_models import GraphConfig
from sv1_data.service import load_dataset
from sv2_attack_graph.service import build_graph

ROOT = Path(__file__).resolve().parents[2]

@pytest.fixture
def dataset():
    return load_dataset(ROOT / 'sv2_attack_graph' / 'fixtures')

@pytest.fixture
def config():
    return GraphConfig(model_version='1.0.0',entry_point_ids=['INTERNET'],target_asset_ids=['DB01'],max_depth=5,max_paths=10)

def test_internet_to_database(dataset,config):
    result=build_graph(dataset,[],config)
    assert result.search_complete
    assert len(result.paths)==1
    assert result.paths[0].asset_ids==['INTERNET','WEB01','APP01','DB01']
    assert result.paths[0].finding_ids==['F-WEB-001','F-APP-001','F-DB-001']

def test_patching_each_chain_link_blocks(dataset,config):
    for fid in ['F-WEB-001','F-APP-001','F-DB-001']:
        assert build_graph(dataset,[fid],config).paths==[]

def test_unrelated_patch_preserves_path_id(dataset,config):
    a=build_graph(dataset,[],config)
    b=build_graph(dataset,['F-TEST-001'],config)
    assert a.paths[0].path_id==b.paths[0].path_id

def test_no_rules_does_not_assume_exploit(dataset,config):
    d=dataset.model_copy(deep=True)
    d.exploit_rules=[]
    assert build_graph(d,[],config).paths==[]

def test_blocked_connection(dataset,config):
    d=dataset.model_copy(deep=True)
    d.connections[1].allowed=False
    assert build_graph(d,[],config).paths==[]

def test_depth_cutoff(dataset,config):
    c=config.model_copy(update={'max_depth':2})
    r=build_graph(dataset,[],c)
    assert r.paths==[] and not r.search_complete and r.warnings

def test_missing_patch(dataset,config):
    with pytest.raises(InvalidReferenceError): build_graph(dataset,['missing'],config)

def test_bad_version(dataset,config):
    with pytest.raises(UnsupportedVersionError): build_graph(dataset,[],config.model_copy(update={'model_version':'2.0.0'}))

def test_strict_model():
    with pytest.raises(Exception): GraphConfig(model_version='1.0.0',entry_point_ids=['INTERNET'],target_asset_ids=['DB01'],max_depth=0,max_paths=1)

def test_rule_requires_matching_service(dataset,config):
    d=dataset.model_copy(deep=True)
    d.connections[1].target_service_id='S-DB-5432'
    with pytest.raises(InvalidReferenceError): build_graph(d,[],config)

def test_no_mutation(dataset,config):
    before=dataset.model_dump_json()
    build_graph(dataset,['F-APP-001'],config)
    assert dataset.model_dump_json()==before

def test_trust_requires_evidence(dataset,config):
    d=dataset.model_copy(deep=True)
    r=d.exploit_rules[1];r.rule_type='trust';r.required_finding_id=None;r.evidence=[]
    with pytest.raises(ContractError): build_graph(d,[],config)

def test_max_paths(dataset,config):
    c=config.model_copy(update={'target_asset_ids':['APP01','DB01','TEST01'],'max_paths':1})
    r=build_graph(dataset,[],c)
    assert len(r.paths)==1 and not r.search_complete
