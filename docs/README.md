# SentinelAI documentation

Start here when writing the research paper. Each document below maps to one or more paper sections.

| Document | What it covers | Use it for paper section |
|----------|----------------|--------------------------|
| [Research_Paper_Guide.md](Research_Paper_Guide.md) | Paper outline, draft abstract, contributions, figure/table plan, reference list, writing checklist | Whole paper (start here) |
| [System_Architecture.md](System_Architecture.md) | Layers, components, data flow, agents, API, desktop app, storage, deployment | III. System Architecture |
| [Methodology_and_Algorithms.md](Methodology_and_Algorithms.md) | NIDS feature bridge, hybrid port rule, OOD policy, live routing, risk formula, HIDS model, trust model, self-protection | IV. Methodology |
| [Evaluation_and_Results.md](Evaluation_and_Results.md) | Measured results, experiment protocols, tables to fill, case studies, threats to validity | V. Evaluation, VI. Discussion |
| [Phase1_Progress_Report.md](Phase1_Progress_Report.md) | Dataset study, EDA, port leakage, duplicate-row experiments A–C (3-class) | V-A. Offline NIDS baseline |
| [ML_Package_v2.md](ML_Package_v2.md) | Frozen 6-class CIC model (rollback) | IV-A. Model versions |
| [ML_Package_v3.md](ML_Package_v3.md) | Active 7-class CIC + lab domain-adapted model | IV-A. Model versions |
| [features_list.md](features_list.md) | The 77-feature contract | Appendix A |
| [Project_Gameplan_Blueprint.md](Project_Gameplan_Blueprint.md) | Roadmap, phases, scope ladder, team split | Project history, Future work |
| [Supervisor_Presentation_Script.md](Supervisor_Presentation_Script.md) | Talk track and demo script | Presentation / viva |

Related material outside `docs/`:

| Location | What it covers |
|----------|----------------|
| `soar/README.md` | Agent specifications, risk formula, self-protection table |
| `soar/contracts/teammate_contracts.md` | Model, sensor, host-event and API contracts between team members |
| `hids/README.md`, `hids/dataset/README.md` | HIDS sensors, simulator, dataset and model |
| `dashboard/README.md`, `dashboard/backend-dist/README.md` | Desktop app and Windows installer build |
