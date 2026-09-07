[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8765,
    [string]$BindAddress = "127.0.0.1",
    [string]$FrontendDir = "",
    [string]$ControlPlaneDir = "",
    [switch]$NoBrowser,
    [switch]$ApiOnly,
    [switch]$Workbench,
    [switch]$GrantInstanceOperator,
    [switch]$TrustControlPlaneHeaders,
    [switch]$RebuildFixture,
    [switch]$ValidateFixture
)

$ErrorActionPreference = "Stop"
$EnvironmentName = "router-dump-analyzer-demo"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$FrontendRoot = if ([string]::IsNullOrWhiteSpace($FrontendDir)) {
    Join-Path $RepositoryRoot "frontend"
}
else {
    (Resolve-Path -LiteralPath $FrontendDir).Path
}
$FrontendManifest = Join-Path $FrontendRoot "frontend-manifest.json"
$ControlPlaneRoot = if ([string]::IsNullOrWhiteSpace($ControlPlaneDir)) {
    Join-Path $RepositoryRoot ".runtime\control-plane"
}
else {
    [System.IO.Path]::GetFullPath($ControlPlaneDir)
}
$FixtureAssemblyArgument = "demo\fixtures\router-state-lab-demo.tgz"

function Find-CondaExecutable {
    $command = Get-Command conda.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path $env:USERPROFILE "anaconda3\Scripts\conda.exe"),
        (Join-Path $env:USERPROFILE "miniconda3\Scripts\conda.exe"),
        (Join-Path $env:LOCALAPPDATA "miniconda3\Scripts\conda.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    throw "Conda was not found. Run .\scripts\setup_demo.cmd after installing Miniconda or Anaconda."
}

$CondaExecutable = Find-CondaExecutable
$CondaRoot = Split-Path -Parent (Split-Path -Parent $CondaExecutable)
$AnalyzerPython = Join-Path $CondaRoot "envs\$EnvironmentName\python.exe"
if (-not (Test-Path -LiteralPath $AnalyzerPython)) {
    throw "The Conda environment '$EnvironmentName' is missing. Run .\scripts\setup_demo.cmd first."
}

# Opt-in workbench/operator authority never follows DNS or the off-loopback
# development override. Core validates the listener and resolver again.
if ($Workbench -or $GrantInstanceOperator) {
    $LoopbackCheck = @'
import ipaddress
import sys
try:
    allowed = ipaddress.ip_address(sys.argv[1]).is_loopback
except ValueError:
    allowed = False
raise SystemExit(0 if allowed else 2)
'@
    & $AnalyzerPython -c $LoopbackCheck $BindAddress
    if ($LASTEXITCODE -ne 0) {
        throw "-Workbench and -GrantInstanceOperator require a numeric loopback -BindAddress (127.0.0.1 or ::1); -TrustControlPlaneHeaders cannot override this restriction."
    }
}

$PreviousPythonUtf8 = $env:PYTHONUTF8
$PreviousPythonIoEncoding = $env:PYTHONIOENCODING
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

# Windows PowerShell 5.1 otherwise decodes Python's forced UTF-8 stdout with
# the legacy console code page. That corrupts a selected fixture path whenever
# the repository contains non-ASCII components, such as "文档".
$PreviousConsoleOutputEncoding = [Console]::OutputEncoding
$PreviousOutputEncoding = $OutputEncoding
$Utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
[Console]::OutputEncoding = $Utf8NoBom
$OutputEncoding = $Utf8NoBom

Push-Location $RepositoryRoot
try {
    if (-not $ApiOnly -and -not (Test-Path -LiteralPath $FrontendManifest)) {
        throw "Frontend distribution is incomplete: $FrontendManifest was not found."
    }
    Write-Host (
        "[fixture] Ensuring the canonical full-scale multi-node assembly..."
    )
    $EnsureArguments = @(
        "-m", "rsl_demo_generator",
        "--ensure-launchable", $FixtureAssemblyArgument,
        "--path-only"
    )
    if ($RebuildFixture) {
        $EnsureArguments += "--force-rebuild"
    }
    $EnsureTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $SelectedFixtureOutput = & $AnalyzerPython @EnsureArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Could not prepare the full-scale multi-node fixture."
    }
    $EnsureTimer.Stop()
    $SelectedFixture = [string](
        $SelectedFixtureOutput | Select-Object -Last 1
    )
    $SelectedFixture = $SelectedFixture.Trim()
    if (
        [string]::IsNullOrWhiteSpace($SelectedFixture) -or
        -not (Test-Path -LiteralPath $SelectedFixture -PathType Leaf)
    ) {
        throw "Generator did not return a regular launch fixture path."
    }
    Write-Host (
        "[fixture] Launch input ready in {0:N1} s: {1}" -f
        $EnsureTimer.Elapsed.TotalSeconds,
        $SelectedFixture
    )

    if ($ValidateFixture) {
        Write-Host "[fixture] Validating the existing generated assembly..."
        $ValidationTimer = [System.Diagnostics.Stopwatch]::StartNew()
        & $AnalyzerPython @(
            "-m", "rsl_demo_generator",
            "--validate", $SelectedFixture
        )
        if ($LASTEXITCODE -ne 0) {
            throw "Full fixture validation failed."
        }
        $ValidationTimer.Stop()
        Write-Host (
            "[fixture] Validation finished in {0:N1} s." -f
            $ValidationTimer.Elapsed.TotalSeconds
        )
    }

    $CoreArguments = @(
        "-m", "router_dump_analyzer",
        "--plugin", "demo_router",
        "--input", $SelectedFixture,
        "--host", $BindAddress,
        "--port", [string]$Port,
        "--frontend-dir", $FrontendRoot,
        "--control-plane-dir", $ControlPlaneRoot
    )
    if ($ApiOnly) {
        $CoreArguments += "--api-only"
    }
    if ($Workbench) {
        $CoreArguments += @(
            "--plugin-composition-deployment-module",
            "rsl_demo_plugin.deployment:build_plugin_deployment",
            "--private-analysis-deployment-module",
            "rsl_demo_plugin.offline_analysis:build_offline_analysis_deployment"
        )
    }
    if ($TrustControlPlaneHeaders -or $Workbench) {
        $CoreArguments += "--trust-control-plane-headers"
    }
    if ($GrantInstanceOperator) {
        $CoreArguments += "--grant-instance-operator"
    }
    if ($NoBrowser) {
        $CoreArguments += "--no-browser"
    }

    Write-Host "Using generated assembly: $SelectedFixture"
    Write-Host "Single-node and fabric views read this same generated assembly."
    Write-Host "Durable sessions, imports, and review data: $ControlPlaneRoot"
    if ($Workbench) {
        Write-Host "Workbench: exact demo parser/evidence composition; trusted tenant/principal headers on numeric loopback only."
        Write-Host "Local runner: demo.scripted-evidence-walk 1.0.0; scripted demonstration, not a model; client-safe evidence only."
        Write-Host "Open /manage for durable workflows. No startup data is published and no private-analysis policy is enabled automatically."
        Write-Host "Optional compact inputs (run separately): python -m rsl_demo_generator.workbench --output-dir .runtime/workbench-inputs"
    }
    if ($GrantInstanceOperator) {
        Write-Host "Explicit local development grant: control-plane:instance-operator."
    }
    if ($ApiOnly) {
        Write-Host "Starting Router State Lab backend API at http://${BindAddress}:$Port"
        Write-Host "Run 'npm --prefix frontend run serve -- --backend http://${BindAddress}:$Port' in another terminal for the split frontend."
    }
    else {
        Write-Host "Starting Router State Lab at http://${BindAddress}:$Port"
    }
    Write-Host "The server intentionally stays attached to this terminal. Press Ctrl+C to stop it."
    & $AnalyzerPython @CoreArguments
    if ($LASTEXITCODE -ne 0) {
        throw "The core analyzer did not start. Run .\scripts\setup_demo.cmd first."
    }
}
finally {
    Pop-Location
    if ($null -eq $PreviousPythonUtf8) {
        Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue
    }
    else {
        $env:PYTHONUTF8 = $PreviousPythonUtf8
    }
    if ($null -eq $PreviousPythonIoEncoding) {
        Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue
    }
    else {
        $env:PYTHONIOENCODING = $PreviousPythonIoEncoding
    }
    $OutputEncoding = $PreviousOutputEncoding
    [Console]::OutputEncoding = $PreviousConsoleOutputEncoding
}
