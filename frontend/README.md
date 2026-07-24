# Router State Lab frontend

This directory is the browser application boundary. It owns all HTML pages,
JavaScript, CSS, page routes, and their deployment manifest. The Python backend
does not contain or construct page templates; it reads
`frontend-manifest.json` through a generic static-host adapter.

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
references, and JavaScript syntax without installing packages.
