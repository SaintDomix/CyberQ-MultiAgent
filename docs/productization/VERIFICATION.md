# Productization verification

625 Python tests passed, including 26 application contracts, 15 accepted-v2
runtime tests, 44 M2D live tests and 80 Fusion/CQI tests. 28 frontend tests
passed, including reused M4 utilities and seven-page render/semantic tests.
The final Vite production build passed with local dependencies.

Headless Chromium acceptance exercised all seven pages at 1920×1080:
navigation, real locked metric rendering, SHAP drawer, dismissed-posture filter,
contextual Fusion, incident detail, explicit unavailable LIVE_LAB state and the
suppressed isolated anomaly in benign replay. Browser requests were intercepted
locally; no external requests or live jobs were started. Visual screenshots
were inspected from `/tmp/product_overview_1920.png` and
`/tmp/product_research_1920.png`. Test artifacts remain temporary.

The sandbox blocks the thread/event-loop IPC needed by FastAPI and Chromium;
those checks ran with the explicit IPC allowance outside the sandbox. Model
fitting and external network calls remain guarded in application unit tests.

All 1,279 pre-existing files under data/evidence/outputs are byte-identical.
Accepted-v2 verification and Model v1 verification passed; frozen Branch1/
Branch2/Fusion/reporting diff is empty. Tracked and new-source whitespace checks
passed. See `ACCEPTANCE_RECEIPT.json` for source identities and exact snapshot.

No models were retrained, no research metrics were recalculated, no live Apache
records were opened, no research outputs were rewritten, and no commit/tag was
created. CQI was calculated only as a new in-memory application projection using
the frozen scoring policy and actual saved predictions.

Operator acceptance still needed: launch the local dashboard, verify Apache
read permission, explicitly start the accepted passive monitor, browse Moodle
normally, wait for complete ten-second windows plus grace, verify updating
observations/CQI, then stop safely. Do not generate attacks from the dashboard.
No new full v2 narrative report export or population-scale deployment claim is
included; the report link is labelled as the historical accepted v1 M3C report.
