# Freeze the protection engine and stage it for the desktop installer.
#   powershell -ExecutionPolicy Bypass -File packaging\build_backend.ps1
# Result: dashboard\backend-dist\sentinel-backend.exe (+ _internal\), which electron-builder
# copies to resources\backend\ and the desktop app starts instead of the source checkout.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

Push-Location $root
try {
    & $python -m PyInstaller --version | Out-Null
    if ($LASTEXITCODE -ne 0) { & $python -m pip install pyinstaller; if ($LASTEXITCODE -ne 0) { throw "pip install pyinstaller failed" } }

    & $python -m PyInstaller packaging\sentinel-backend.spec --noconfirm --clean `
        --distpath build\pyinstaller\dist --workpath build\pyinstaller\work
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

    $out = Join-Path $root "dashboard\backend-dist"
    Get-ChildItem $out -Force | Where-Object { $_.Name -ne "README.md" } | Remove-Item -Recurse -Force
    Copy-Item -Path (Join-Path $root "build\pyinstaller\dist\sentinel-backend\*") -Destination $out -Recurse -Force

    & (Join-Path $out "sentinel-backend.exe") integrity show
    if ($LASTEXITCODE -ne 0) { throw "Frozen engine failed its smoke test" }
    Write-Host "Engine staged in $out"
}
finally {
    Pop-Location
}
