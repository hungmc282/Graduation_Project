# SV2 — Attack Graph

Implements `build_graph(dataset: DatasetSnapshot, patched_finding_ids: list[str], config: GraphConfig) -> GraphResult`.

## Compatibility

- Uses **canonical** `DatasetSnapshot`, `Connection`, `ExploitRule` from `common.schemas` on `main`, and canonical errors/validation from `common.errors`, `sv1_data.service`.
- `GraphConfig`, `AttackPath`, `GraphResult` are defined temporarily in `sv2_attack_graph.graph_models`, **because they do not exist yet in `common.schemas`**. Their fields follow ARCHITECTURE.md §6.5. Once the shared contract is approved, move these declarations to common and update imports; do not maintain duplicates.
- Only commit `sv2_attack_graph/`. Merge `origin/main` into your SV2 branch before testing, so canonical modules exist; do not copy common or SV1 from old ZIPs.

## Install & run (repository root)

```bash
py -3.11 -m pip install 'pydantic>=2,<3' 'networkx>=3,<4' pytest
py -3.11 -m pytest -q sv2_attack_graph/tests
py -3.11 -m sv2_attack_graph.demo
```

## Model assumptions and limits

- Directed allowed connections and evidence-based rules only; network reachability alone never creates an attack path.
- Entry starts with state `initial`. Every rule must require the current state and produces the next state.
- An exploit requires a finding on the destination asset. Patching disables rules requiring that finding. No automatic CVE exploit generation or real scanning.
- Simple paths do not revisit assets; targets terminate paths.
- `max_depth` counts rule transitions. Incomplete enumeration is flagged via `search_complete=False`.
- Stable `path_id` is a SHA-256 digest of the ordered rule IDs.
- Synthetic fixture Internet → Web → App → DB demonstrates path elimination when F-APP-001 is patched.

## Handoff

SV3/SV4 should call `sv2_attack_graph.build_graph`, not reimplement graph traversal. `GraphResult` schema migration to `common` is pending group approval.
