[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$EnvironmentName = "router-dump-analyzer-demo"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EnvironmentFile = Join-Path $RepositoryRoot "environment.yml"
$PreviousPythonUtf8 = $env:PYTHONUTF8
$PreviousPythonIoEncoding = $env:PYTHONIOENCODING

# Conda 23.x can otherwise encode the pip command with the Windows ANSI code
# page and fail when this repository lives below a Unicode path such as `文档`.
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
    throw "Conda was not found. Install Miniconda or Anaconda, then rerun this script."
}

function Invoke-Conda {
    param([string[]]$CondaArguments)
    & $script:CondaExecutable @CondaArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Conda command failed with exit code $LASTEXITCODE."
    }
}

$CondaExecutable = Find-CondaExecutable
Push-Location $RepositoryRoot
try {
    $environmentData = & $CondaExecutable env list --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect Conda environments."
    }
    $exists = $environmentData.envs | Where-Object { (Split-Path -Leaf $_) -eq $EnvironmentName }
    if ($exists) {
        $runningDemo = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ExecutablePath -like "*\envs\$EnvironmentName\python.exe" -and
                $_.CommandLine -like "*router-dump-demo*"
            }
        if ($runningDemo) {
            $processIds = ($runningDemo | Select-Object -ExpandProperty ProcessId) -join ", "
            throw "Router State Lab is still running (PID $processIds). Stop it before updating the Conda environment."
        }
        Write-Host "Updating Conda environment '$EnvironmentName'..."
        Invoke-Conda @("env", "update", "--name", $EnvironmentName, "--file", $EnvironmentFile, "--prune")
    }
    else {
        Write-Host "Creating Conda environment '$EnvironmentName'..."
        Invoke-Conda @("env", "create", "--file", $EnvironmentFile)
    }

    Write-Host "Running the demo test suite inside the Conda environment..."
    Invoke-Conda @(
        "run", "--no-capture-output", "--name", $EnvironmentName,
        "python", "-m", "unittest", "discover", "-s", "tests", "-v"
    )
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

Write-Host "Ready. Launch with: .\scripts\launch_demo.cmd"
