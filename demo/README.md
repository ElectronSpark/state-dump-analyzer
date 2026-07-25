# Router State Lab demo distribution

This directory is the independently installable review application for the
Router Dump Analyzer core. It contains the FastAPI server, synthetic fixture
adapters, topology and route scenarios, and the browser distribution. Its
dependency on `router-dump-analyzer-core` is intentionally one-way: the core
does not import or install this package.

From the repository root, install both editable distributions with:

```powershell
python -m pip install -e ".[test]"
python -m pip install -e "./demo[test]"
```

The repository launchers generate or validate the packed fixture before
starting the application:

```powershell
.\scripts\launch_demo.cmd -NoBrowser
```

For a fixture that has already been prepared, the installed console command is:

```powershell
router-dump-demo --fixture-archive samples/generated-scale/router-state-lab-100k.tgz --full-scale
```

Device plug-in authors should depend only on `router-dump-analyzer-core` and
use the minimal package in `examples/minimal_plugin/`; the synthetic adapters
in this directory are demo data producers, not production ingestion plug-ins.
