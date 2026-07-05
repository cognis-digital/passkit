# passkit setup for Windows (PowerShell).
# Creates (or reuses) a .venv, installs passkit in editable mode with dev
# extras, and verifies the CLI runs. Idempotent: safe to run repeatedly.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# Interpreter selection. $PyExe is the executable; $PyArgs are leading args
# (e.g. a version selector for the py launcher). Invoke as: & $PyExe @PyArgs ...
$script:PyExe = $null
$script:PyArgs = @()

function Test-Py310 {
    # Returns $true if "<exe> <preargs>" launches a working Python 3.10+.
    param([string]$Exe, [string[]]$PreArgs)
    $probe = 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)'
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Exe @PreArgs "-c" $probe 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $old
    }
}

function Find-Python {
    # Prefer the py launcher with an explicit 3.10+ selector, then a bare
    # py/python/python3 that already satisfies 3.10+.
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in @("-3.12", "-3.11", "-3.10", "-3")) {
            if (Test-Py310 -Exe "py" -PreArgs @($v)) {
                $script:PyExe = "py"; $script:PyArgs = @($v); return $true
            }
        }
    }
    foreach ($name in @("python", "python3", "py")) {
        if (Get-Command $name -ErrorAction SilentlyContinue) {
            if (Test-Py310 -Exe $name -PreArgs @()) {
                $script:PyExe = $name; $script:PyArgs = @(); return $true
            }
        }
    }
    return $false
}

if (-not (Find-Python)) {
    Write-Error "No Python 3.10+ interpreter found on PATH. Install Python 3.10+ from python.org."
    exit 1
}

$pyVer = (& $PyExe @PyArgs "-c" "import sys; print('%d.%d' % sys.version_info[:2])")
Write-Host ">> Using $PyExe $($PyArgs -join ' ') (Python $pyVer)"

# --- create / reuse virtualenv -------------------------------------------
$venv = Join-Path $PSScriptRoot ".venv"
if (Test-Path $venv) {
    Write-Host ">> Reusing existing virtualenv at .venv"
} else {
    Write-Host ">> Creating virtualenv at .venv"
    & $PyExe @PyArgs "-m" "venv" $venv
}

$activate = Join-Path $venv "Scripts\Activate.ps1"
if (-not (Test-Path $activate)) {
    Write-Error "Virtualenv activation script not found at $activate"
    exit 1
}
& $activate

# The venv's python (activation puts it first on PATH, but be explicit).
$venvPy = Join-Path $venv "Scripts\python.exe"

# --- install --------------------------------------------------------------
Write-Host ">> Upgrading pip"
& $venvPy -m pip install --upgrade pip | Out-Null

Write-Host ">> Installing passkit (editable) with dev + yaml extras"
& $venvPy -m pip install -e ".[dev,yaml]"

# --- verify ---------------------------------------------------------------
Write-Host ">> Verifying CLI"
& $venvPy -m passkit --version
& $venvPy -m passkit --help | Out-Null

Write-Host ""
Write-Host "============================================================"
Write-Host " passkit is installed. Next steps:"
Write-Host "============================================================"
Write-Host " Activate the environment in a new shell:"
Write-Host "     .\.venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host " Try the CLI:"
Write-Host "     passkit challenge --ttl 120"
Write-Host "     passkit --help"
Write-Host ""
Write-Host " Run the tests:"
Write-Host "     pytest -q            # or:  make test"
Write-Host ""
Write-Host " Run the demos:"
Write-Host "     python demos\run_all.py   # or:  make demo"
Write-Host "============================================================"
