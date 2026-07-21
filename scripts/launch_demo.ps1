[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8765,
    [string]$BindAddress = "127.0.0.1",
    [switch]$NoBrowser,
    [switch]$RebuildFixture
)

$ErrorActionPreference = "Stop"
$EnvironmentName = "router-dump-analyzer-demo"
$MatchedEventTarget = 125000
$ResourceTarget = 100000
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$FixtureArchiveArgument = "samples\generated-scale\router-state-lab-100k.tgz"
$FixtureArchive = Join-Path $RepositoryRoot $FixtureArchiveArgument
$ScaleScenario = Join-Path $RepositoryRoot "samples\generated-scale\scenario.json"
$ReviewManifest = Join-Path $RepositoryRoot "samples\generated\unpacked\node-a\manifest.json"
$ReviewResources = Join-Path $RepositoryRoot "samples\generated\illustrative\resources.jsonl"
$PreviousPythonUtf8 = $env:PYTHONUTF8
$PreviousPythonIoEncoding = $env:PYTHONIOENCODING
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

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
$DemoPython = Join-Path $CondaRoot "envs\$EnvironmentName\python.exe"
if (-not (Test-Path -LiteralPath $DemoPython)) {
    throw "The Conda environment '$EnvironmentName' is missing. Run .\scripts\setup_demo.cmd first."
}

function Invoke-DemoPython {
    param([string[]]$PythonArguments)
    $StartParameters = @{
        FilePath = $script:DemoPython
        ArgumentList = $PythonArguments
        NoNewWindow = $true
        Wait = $true
        PassThru = $true
    }
    $CondaProcess = Start-Process @StartParameters
    if ($CondaProcess.ExitCode -ne 0) {
        throw "Fixture generation failed with exit code $($CondaProcess.ExitCode)."
    }
}

Push-Location $RepositoryRoot
try {
    $ScaleReady = Test-Path -LiteralPath $ScaleScenario
    if ($ScaleReady) {
        try {
            $Scenario = Get-Content -Raw -LiteralPath $ScaleScenario | ConvertFrom-Json
            $ScaleReady = (
                $Scenario.scenario_id -eq "evpn-multihome-mass-failover-v2" -and
                [int64]$Scenario.scale.events -ge $MatchedEventTarget -and
                [int64]$Scenario.scale.resources -eq $ResourceTarget
            )
        }
        catch {
            $ScaleReady = $false
        }
    }
    $ScaleRebuilt = $false
    if ($RebuildFixture -or -not $ScaleReady) {
        Write-Host "Generating the deterministic $MatchedEventTarget matched-event EVPN scale corpus..."
        Invoke-DemoPython @(
            "scripts\generate_scale_fixtures.py",
            "--events", [string]$MatchedEventTarget,
            "--resources", [string]$ResourceTarget
        )
        $ScaleRebuilt = $true
    }

    if (
        $RebuildFixture -or
        -not (Test-Path -LiteralPath $ReviewManifest) -or
        -not (Test-Path -LiteralPath $ReviewResources)
    ) {
        Write-Host "Generating the browser-sized review projection..."
        Invoke-DemoPython @(
            "scripts\generate_sample_bundle.py"
        )
    }

    if (
        $RebuildFixture -or
        $ScaleRebuilt -or
        -not (Test-Path -LiteralPath $FixtureArchive)
    ) {
        Write-Host "Packing CTF logs and heterogeneous resource tables into one TGZ..."
        Invoke-DemoPython @(
            "scripts\generate_packed_scale_bundle.py",
            "--output", $FixtureArchiveArgument
        )
    }

    $DemoArguments = @(
        "-m", "router_dump_analyzer.demo_app",
        "--host", $BindAddress,
        "--port", [string]$Port,
        "--fixture-archive", $FixtureArchiveArgument,
        "--full-scale"
    )
    if (-not $NoBrowser) {
        $DemoArguments += "--open-browser"
    }

    Write-Host "Using packed fixture: $FixtureArchive"
    Write-Host "Loading at least $MatchedEventTarget matched events across $ResourceTarget resources."
    Write-Host "Starting Router State Lab at http://${BindAddress}:$Port"
    $DemoStartParameters = @{
        FilePath = $DemoPython
        ArgumentList = $DemoArguments
        NoNewWindow = $true
        Wait = $true
        PassThru = $true
    }
    $DemoProcess = Start-Process @DemoStartParameters
    if ($DemoProcess.ExitCode -ne 0) {
        throw "The demo did not start. Run .\scripts\setup_demo.cmd first."
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
}
