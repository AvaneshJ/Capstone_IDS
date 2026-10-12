# PyInstaller recipe for the SentinelAI protection engine (onedir build).
# Build:  packaging\build_backend.ps1   (output copied to dashboard\backend-dist\)
#
# Layout inside the bundle mirrors how the code finds its files:
#   models/*.pkl|*.joblib       config.paths.MODELS_DIR (ROOT/models)
#   database/schema.sql         soar/database/db_manager.py (imported as `database.db_manager`)
#   rules/policies.yaml         soar/rules/policy_engine.py (imported as `rules.policy_engine`)
# Runtime output (database, logs, reports, token, manifest) goes to %PROGRAMDATA%\SentinelAI.
import os
from glob import glob

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
SOAR = os.path.join(ROOT, "soar")

datas = [(path, "models") for path in glob(os.path.join(ROOT, "models", "*.pkl")) + glob(os.path.join(ROOT, "models", "*.joblib"))]
datas += [
    (os.path.join(SOAR, "database", "schema.sql"), "database"),
    (os.path.join(SOAR, "rules", "policies.yaml"), "rules"),
]
datas += collect_data_files("pydivert")  # WinDivert64.dll / WinDivert64.sys (LGPL)
datas += collect_data_files("reportlab")
datas += collect_data_files("xgboost")

binaries = collect_dynamic_libs("xgboost") + collect_dynamic_libs("pydivert")

hiddenimports = (
    collect_submodules("api")
    + collect_submodules("agents")
    + collect_submodules("core")
    + collect_submodules("adapters")
    + collect_submodules("rules")
    + collect_submodules("database")
    + collect_submodules("contracts")
    + collect_submodules("config")
    + collect_submodules("hids", filter=lambda name: ".tests" not in name and ".dataset" not in name)
    + collect_submodules("nids", filter=lambda name: ".tests" not in name)
    + collect_submodules("uvicorn")
    + collect_submodules("scapy.layers")
    + collect_submodules("scapy.arch")
    + collect_submodules("cicflowmeter")
    + collect_submodules("pydivert")
    + collect_submodules("plyer.platforms.win")
    + ["tests.mock_traffic", "demo_runner", "sklearn.ensemble", "sklearn.pipeline", "sklearn.preprocessing"]
)

a = Analysis(
    [os.path.join(SOAR, "main.py")],
    pathex=[SOAR, ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "IPython", "jupyter", "pytest", "notebook"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sentinel-backend",
    console=True,  # the desktop app starts it hidden (windowsHide) and reads stdout into engine.log
    icon=os.path.join(ROOT, "dashboard", "electron", "assets", "icon.ico") if os.path.exists(os.path.join(ROOT, "dashboard", "electron", "assets", "icon.ico")) else None,
)

coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="sentinel-backend")
