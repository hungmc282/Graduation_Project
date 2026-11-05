# Danh sách file để nhóm đối chiếu

Mốc main/sv1-data: `9f9842b31cd857749a255f3242207d4c9bf38c51`. Phần dưới ghi file của bản local; chưa tính ba tài liệu bàn giao PR_TEST, FILES_CHANGED_TEST và TEST_RESULTS_TEST.

Khác nội dung: 11. Chỉ có bản local: 126.

## File khác nội dung

- `.gitignore`
- `README.md`
- `common/schemas.py`
- `sv1_data/README.md`
- `sv1_data/adapters/nmap_xml.py`
- `sv1_data/adapters/trivy_json.py`
- `sv1_data/enrichment/cache.py`
- `sv1_data/enrichment/service.py`
- `sv1_data/pipeline.py`
- `sv2_attack_graph/graph_models.py`
- `sv4_app_llm/README.md`

## File bổ sung theo nhóm

### .streamlit

- `.streamlit/config.toml`

### data

- `data/demo_reports/after-F01/analysis.json`
- `data/demo_reports/after-F01/details.json`
- `data/demo_reports/before-F01/analysis.json`
- `data/demo_reports/before-F01/details.json`
- `data/samples/sv1_input_checks/README.md`
- `data/samples/sv1_input_checks/conflict.json`
- `data/samples/sv1_input_checks/duplicates.json`
- `data/samples/sv1_input_checks/invalid-port.json`
- `data/samples/sv1_input_checks/invalid-trivy.json`
- `data/samples/sv1_input_checks/nmap-conflict.xml`
- `data/samples/sv1_input_checks/nmap-invalid.xml`
- `data/samples/sv1_input_checks/nmap.xml`
- `data/samples/sv1_input_checks/trivy-invalid.json`
- `data/samples/sv1_milestone1/README.md`
- `data/samples/sv1_milestone1/expected.json`
- `data/samples/sv1_milestone1/run1/config.json`
- `data/samples/sv1_milestone1/run1/feeds/epss_scores-current.csv.gz`
- `data/samples/sv1_milestone1/run1/feeds/known_exploited_vulnerabilities.json`
- `data/samples/sv1_milestone1/run1/inventory.csv`
- `data/samples/sv1_milestone1/run1/nmap.xml`
- `data/samples/sv1_milestone1/run1/trivy.json`
- `data/samples/sv1_milestone1/run2/config.json`
- `data/samples/sv1_milestone1/run2/feeds/epss_scores-current.csv.gz`
- `data/samples/sv1_milestone1/run2/feeds/known_exploited_vulnerabilities.json`
- `data/samples/sv1_milestone1/run2/inventory.csv`
- `data/samples/sv1_milestone1/run2/nmap.xml`
- `data/samples/sv1_milestone1/run2/trivy.json`

### docs

- `docs/CONSOLIDATION.md`
- `docs/decisions/001-sv2-integration.md`
- `docs/design/dashboard-concepts.html`
- `docs/sv1/milestone1-engine-walkthrough.md`
- `docs/sv1/milestone2-input-and-merge.md`

### pyproject.toml

- `pyproject.toml`

### sv1_data

- `sv1_data/demo.py`
- `sv1_data/merging.py`

### sv3_risk

- `sv3_risk/IMPLEMENTATION.md`
- `sv3_risk/__init__.py`
- `sv3_risk/data/scenarios/chain/PROVENANCE.md`
- `sv3_risk/data/scenarios/chain/config.json`
- `sv3_risk/data/scenarios/chain/dataset.json`
- `sv3_risk/data/scenarios/chain/topology-context.json`
- `sv3_risk/data/scenarios/diamond/PROVENANCE.md`
- `sv3_risk/data/scenarios/diamond/config.json`
- `sv3_risk/data/scenarios/diamond/dataset.json`
- `sv3_risk/data/scenarios/diamond/topology-context.json`
- `sv3_risk/data/scenarios/multi-target/PROVENANCE.md`
- `sv3_risk/data/scenarios/multi-target/config.json`
- `sv3_risk/data/scenarios/multi-target/dataset.json`
- `sv3_risk/data/scenarios/multi-target/topology-context.json`
- `sv3_risk/demo.py`
- `sv3_risk/docs/REQUIREMENTS_TRACEABILITY.md`
- `sv3_risk/docs/RISK_MODEL_V1.md`
- `sv3_risk/docs/SV3_SCOPE.md`
- `sv3_risk/docs/THREAT_MODEL.md`
- `sv3_risk/docs/USE_CASES.md`
- `sv3_risk/docs/ranking-method.md`
- `sv3_risk/errors.py`
- `sv3_risk/prioritization.py`
- `sv3_risk/research/__init__.py`
- `sv3_risk/research/benchmark.py`
- `sv3_risk/research/cli.py`
- `sv3_risk/research/engine.py`
- `sv3_risk/research/evaluate.py`
- `sv3_risk/research/remediation.py`
- `sv3_risk/research/service.py`
- `sv3_risk/service.py`
- `sv3_risk/tests/fixtures/analysis-config.json`
- `sv3_risk/tests/fixtures/dataset-week1.json`
- `sv3_risk/tests/fixtures/graph-unpatched.json`
- `sv3_risk/tests/research/test_context_risk.py`
- `sv3_risk/tests/test_prioritization.py`

### sv4_app_llm

- `sv4_app_llm/__init__.py`
- `sv4_app_llm/adapters/__init__.py`
- `sv4_app_llm/adapters/sv1.py`
- `sv4_app_llm/app.py`
- `sv4_app_llm/apps/__init__.py`
- `sv4_app_llm/apps/risk_analysis/__init__.py`
- `sv4_app_llm/apps/risk_analysis/app.py`
- `sv4_app_llm/apps/risk_analysis/dashboard.py`
- `sv4_app_llm/apps/risk_analysis/service.py`
- `sv4_app_llm/config.py`
- `sv4_app_llm/demos/__init__.py`
- `sv4_app_llm/demos/loader.py`
- `sv4_app_llm/llm/__init__.py`
- `sv4_app_llm/llm/dataset.py`
- `sv4_app_llm/llm/ollama.py`
- `sv4_app_llm/reports/__init__.py`
- `sv4_app_llm/reports/export.py`
- `sv4_app_llm/service.py`
- `sv4_app_llm/services/__init__.py`
- `sv4_app_llm/services/analysis.py`
- `sv4_app_llm/services/assistant.py`
- `sv4_app_llm/services/assistant_facts.py`
- `sv4_app_llm/services/enterprise.py`
- `sv4_app_llm/services/websites.py`
- `sv4_app_llm/storage/__init__.py`
- `sv4_app_llm/storage/repository.py`
- `sv4_app_llm/tests/test_dataset_ai.py`
- `sv4_app_llm/tests/test_enterprise.py`
- `sv4_app_llm/tests/test_sv1_integration.py`
- `sv4_app_llm/tests/test_sv4.py`
- `sv4_app_llm/tests/test_website_workflow.py`
- `sv4_app_llm/ui/__init__.py`
- `sv4_app_llm/ui/assistant.py`
- `sv4_app_llm/ui/compact_pages.py`
- `sv4_app_llm/ui/dashboard.py`
- `sv4_app_llm/ui/dataset.py`
- `sv4_app_llm/ui/glass_graph.py`
- `sv4_app_llm/ui/graph_view.py`
- `sv4_app_llm/ui/history.py`
- `sv4_app_llm/ui/legacy/__init__.py`
- `sv4_app_llm/ui/legacy/actions.py`
- `sv4_app_llm/ui/legacy/assets.py`
- `sv4_app_llm/ui/legacy/websites.py`
- `sv4_app_llm/ui/reports.py`
- `sv4_app_llm/ui/theme.py`
- `sv4_app_llm/ui/workspace.py`

### tests

- `tests/integration/test_application.py`
- `tests/integration/test_assistant_patch_facts.py`
- `tests/integration/test_compact_dashboard.py`
- `tests/integration/test_glass_graph.py`
- `tests/integration/test_graph_view.py`
- `tests/sv1_data/test_sv1_input_merge.py`
- `tests/sv1_data/test_sv1_milestone1.py`

### uv.lock

- `uv.lock`

## Đối chiếu riêng với SV2

So với `sv2-attack-graph` tại `8e4660ec43c7f3b8c4ffc97ac6baed8edf046421`, trong phạm vi sv2_attack_graph và common/schemas.py có hai file thay đổi:

- `common/schemas.py`
- `sv2_attack_graph/graph_models.py`

Thuật toán `sv2_attack_graph/service.py` giống bản SV2 ở mốc trên.
