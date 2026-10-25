"""Run from repository root: python -m sv2_attack_graph.demo"""
from pathlib import Path
from .graph_models import GraphConfig
from sv1_data.service import load_dataset
from sv2_attack_graph.service import build_graph

snapshot=load_dataset(Path(__file__).parent/'fixtures')
config=GraphConfig(model_version='1.0.0',entry_point_ids=['INTERNET'],target_asset_ids=['DB01'],max_depth=5,max_paths=100)
for label,patched in [('BEFORE',[]),('AFTER PATCH',['F-APP-001'])]:
    result=build_graph(snapshot,patched,config)
    print(f'{label}: paths={len(result.paths)}, complete={result.search_complete}')
    for path in result.paths:
        print(' -> '.join(path.asset_ids), path.path_id)
