# Router State Lab core frontend

This directory is the core browser-application boundary. It owns all generic
HTML pages, JavaScript, CSS, page routes, and their deployment manifest. Python
does not contain or construct page templates; the optional core web adapter
reads `frontend-manifest.json` and hosts this distribution.

Device plug-ins do not copy or replace these files. They contribute validated
resource icons, labels, dashboards, table layouts, source-record controls,
topology projections, and route presentation declarations that this frontend
renders through core-owned components.

The normal demo launcher serves this distribution from the FastAPI origin, so
the existing `http://127.0.0.1:8765/`, `/topology`, `/node`, and `/assets/*`
URLs continue to work.

For split-process development, start the backend without integrated pages:

```powershell
.\scripts\launch_demo.cmd -ApiOnly -NoBrowser
```

Then, in a second terminal, run the dependency-free Node development server:

```powershell
npm --prefix frontend run serve
```

Open `http://127.0.0.1:4173`. The frontend server proxies the API paths declared
in the manifest to `http://127.0.0.1:8765`, avoiding browser CORS differences
between integrated and split-process operation.

Use `npm --prefix frontend run check` to validate the manifest, local asset
references, JavaScript syntax, single-source frontend boundary, and the
framework-free helper tests under `frontend/tests/`, without installing
packages.
