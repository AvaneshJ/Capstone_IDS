# SentinelAI Dashboard (Phase 6)

React + WebSocket UI will live here once NIDS live inference and SOAR incident JSON are stable.

**Do not start UI work until:**
1. `nids/live_predict.py` works on CSV / lab flows
2. `soar` Detection Agent loads `models/sentinel_xgb_v2.pkl`
3. Incident schema from `soar/core/schemas.py` is agreed with Member 4

Planned stack: React, Recharts, Tailwind, WebSocket against `soar/api/server.py`.
