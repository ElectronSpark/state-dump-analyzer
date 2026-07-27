[CmdletBinding()]
param(
    [int]$Port = 8770,
    [string]$BindAddress = "127.0.0.1",
    [switch]$NoBrowser,
    [switch]$RefreshEnvironment
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$environmentName = "state-dump-generator"

$condaCommand = Get-Command conda.exe -ErrorAction SilentlyContinue
if ($condaCommand) {
    $condaExe = $condaCommand.Source
}
else {
    $condaCandidates = @(
        (Join-Path $env:USERPROFILE "anaconda3\Scripts\conda.exe"),
        (Join-Path $env:USERPROFILE "miniconda3\Scripts\conda.exe"),
        (Join-Path $env:LOCALAPPDATA "anaconda3\Scripts\conda.exe"),
        (Join-Path $env:LOCALAPPDATA "miniconda3\Scripts\conda.exe")
    )
    $condaExe = $condaCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
}

if (-not $condaExe) {
    throw "Conda was not found. Install Miniconda or Anaconda, then reopen this terminal."
}

Push-Location -LiteralPath $projectRoot
try {
    & $condaExe run -n $environmentName python -c "import state_dump_generator" 2>$null
    $environmentReady = $LASTEXITCODE -eq 0

    if (-not $environmentReady) {
        Write-Host "Creating Conda environment '$environmentName'..."
        & $condaExe env create --file environment.yml
        if ($LASTEXITCODE -ne 0) {
            throw "Conda environment creation failed."
        }
    }
    elseif ($RefreshEnvironment) {
        Write-Host "Updating Conda environment '$environmentName'..."
        & $condaExe env update --name $environmentName --file environment.yml --prune
        if ($LASTEXITCODE -ne 0) {
            throw "Conda environment update failed."
        }
    }

    $serveArguments = @(
        "run",
        "--no-capture-output",
        "-n",
        $environmentName,
        "state-dump-generator",
        "serve",
        "--host",
        $BindAddress,
        "--port",
        $Port
    )
    if (-not $NoBrowser) {
        $serveArguments += "--open"
    }

    & $condaExe @serveArguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
