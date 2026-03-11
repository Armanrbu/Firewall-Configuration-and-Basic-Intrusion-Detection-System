# ============================================================================
# NetGuard IDS — Windows MSI Build Script
# ============================================================================
# Prerequisites:
#   - Python 3.10+  (in PATH)
#   - PyInstaller   (pip install pyinstaller)
#   - WiX Toolset   (https://wixtoolset.org)  — candle.exe & light.exe in PATH
#
# Usage:
#   cd packaging\windows
#   .\build_installer.ps1
#
# Output:
#   dist\NetGuard-IDS-2.0.0-win64.msi
# ============================================================================

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$VERSION    = "2.0.0"
$REPO_ROOT  = (Resolve-Path "$PSScriptRoot\..\..")
$DIST_DIR   = "$REPO_ROOT\dist"
$BUILD_DIR  = "$REPO_ROOT\build"
$MSI_OUT    = "$DIST_DIR\NetGuard-IDS-$VERSION-win64.msi"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " NetGuard IDS $VERSION — MSI Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Clean previous builds ───────────────────────────────────────────
Write-Host "[1/6] Cleaning previous build artifacts..." -ForegroundColor Yellow
Remove-Item -Recurse -Force "$DIST_DIR\netguard" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$BUILD_DIR"         -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$DIST_DIR"  | Out-Null

# ── Step 2: Install dependencies ────────────────────────────────────────────
Write-Host "[2/6] Installing Python dependencies..." -ForegroundColor Yellow
& python -m pip install --quiet --upgrade pip
& python -m pip install --quiet -e "$REPO_ROOT[gui,api,cli,ml]"
& python -m pip install --quiet pyinstaller

if ($LASTEXITCODE -ne 0) {
    Write-Error "Dependency installation failed."
    exit 1
}

# ── Step 3: PyInstaller — bundle GUI exe ────────────────────────────────────
Write-Host "[3/6] Building GUI executable with PyInstaller..." -ForegroundColor Yellow
& pyinstaller `
    --noconfirm `
    --clean `
    --name "netguard" `
    --distpath "$DIST_DIR" `
    --workpath "$BUILD_DIR" `
    --onedir `
    --windowed `
    --icon "$REPO_ROOT\assets\icon.ico" `
    --add-data "$REPO_ROOT\config.yaml;." `
    --add-data "$REPO_ROOT\rules;rules" `
    --add-data "$REPO_ROOT\docs;docs" `
    --hidden-import "PySide6.QtCore" `
    --hidden-import "PySide6.QtWidgets" `
    --hidden-import "PySide6.QtGui" `
    --hidden-import "sklearn.ensemble" `
    --hidden-import "sklearn.neighbors" `
    --hidden-import "joblib" `
    "$REPO_ROOT\main.py"

if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller (GUI) failed."; exit 1 }

# ── Step 4: PyInstaller — bundle CLI exe ────────────────────────────────────
Write-Host "[4/6] Building CLI executable with PyInstaller..." -ForegroundColor Yellow
& pyinstaller `
    --noconfirm `
    --clean `
    --name "netguard-cli" `
    --distpath "$DIST_DIR\netguard" `
    --workpath "$BUILD_DIR\cli" `
    --onefile `
    --console `
    --hidden-import "typer" `
    --hidden-import "rich" `
    "$REPO_ROOT\cli\__main__.py"

if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller (CLI) failed."; exit 1 }

# ── Step 5: WiX compile + link ───────────────────────────────────────────────
Write-Host "[5/6] Compiling WiX installer..." -ForegroundColor Yellow
Push-Location "$PSScriptRoot"

# Check WiX is available
if (-not (Get-Command candle.exe -ErrorAction SilentlyContinue)) {
    Write-Warning "candle.exe not found. Install WiX Toolset and add to PATH."
    Write-Warning "Download: https://github.com/wixtoolset/wix3/releases"
    Write-Warning "Skipping MSI build — PyInstaller bundle is at $DIST_DIR\netguard\"
    Pop-Location
    exit 0
}

& candle.exe `
    -nologo `
    -arch x64 `
    -ext WixFirewallExtension `
    -dVERSION="$VERSION" `
    -dREPO_ROOT="$REPO_ROOT" `
    "netguard.wxs" `
    -out "$BUILD_DIR\netguard.wixobj"

if ($LASTEXITCODE -ne 0) { Write-Error "candle.exe failed."; Pop-Location; exit 1 }

& light.exe `
    -nologo `
    -ext WixUIExtension `
    -ext WixFirewallExtension `
    -cultures:en-us `
    "$BUILD_DIR\netguard.wixobj" `
    -out "$MSI_OUT"

Pop-Location

if ($LASTEXITCODE -ne 0) { Write-Error "light.exe failed."; exit 1 }

# ── Step 6: Verify + summary ─────────────────────────────────────────────────
Write-Host "[6/6] Verifying MSI..." -ForegroundColor Yellow
if (Test-Path $MSI_OUT) {
    $size = [math]::Round((Get-Item $MSI_OUT).Length / 1MB, 1)
    Write-Host ""
    Write-Host "✅ MSI built successfully!" -ForegroundColor Green
    Write-Host "   Output : $MSI_OUT" -ForegroundColor Green
    Write-Host "   Size   : ${size} MB"  -ForegroundColor Green
    Write-Host ""
    Write-Host "To install silently:" -ForegroundColor Cyan
    Write-Host "   msiexec /i `"$MSI_OUT`" /qn INSTALLDIR=`"C:\NetGuard IDS`""
} else {
    Write-Error "MSI file not found at $MSI_OUT"
    exit 1
}
