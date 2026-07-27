#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
environment_name="${ROUTER_DUMP_ENV_NAME:-router-dump-analyzer-demo}"
skip_tests=false

usage() {
    cat <<'EOF'
Usage: ./scripts/setup_demo.sh [--skip-tests]

Create or update the WSL-native Conda environment and run the demo tests.
Set CONDA_EXE to select a specific Conda executable.
EOF
}

while (($#)); do
    case "$1" in
        --skip-tests)
            skip_tests=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

find_conda() {
    local candidate
    if [[ -n "${CONDA_EXE:-}" && -x "${CONDA_EXE}" ]]; then
        printf '%s\n' "${CONDA_EXE}"
        return 0
    fi
    if command -v conda >/dev/null 2>&1; then
        command -v conda
        return 0
    fi
    for candidate in \
        "${HOME}/miniforge3/bin/conda" \
        "${HOME}/miniconda3/bin/conda" \
        "${HOME}/anaconda3/bin/conda" \
        "/opt/conda/bin/conda"; do
        if [[ -x "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

if ! conda_executable="$(find_conda)"; then
    printf 'No WSL-native Conda installation was found. Run ./scripts/bootstrap_wsl.sh first.\n' >&2
    exit 1
fi

cd -- "${repository_root}"
environment_json="$("${conda_executable}" env list --json)"
if printf '%s' "${environment_json}" | python3 -c '
import json, os, sys
name = sys.argv[1]
paths = json.load(sys.stdin).get("envs", [])
raise SystemExit(0 if any(os.path.basename(path.rstrip(os.sep)) == name for path in paths) else 1)
' "${environment_name}"; then
    printf 'Updating Conda environment %s...\n' "${environment_name}"
    "${conda_executable}" env update \
        --name "${environment_name}" \
        --file "${repository_root}/environment.yml" \
        --prune
else
    printf 'Creating Conda environment %s...\n' "${environment_name}"
    "${conda_executable}" env create \
        --file "${repository_root}/environment.yml"
fi

# Existing environments may retain the retired demo application distribution
# and its console scripts because those files predate the current package
# split.  Reinstall both current distributions after removing that metadata.
printf 'Removing retired demo application metadata, if present...\n'
"${conda_executable}" run --no-capture-output \
    --name "${environment_name}" \
    python -m pip uninstall --yes router-dump-analyzer-design
"${conda_executable}" run --no-capture-output \
    --name "${environment_name}" \
    python -m pip install --no-deps \
        --editable '.[test,web]' --editable ./demo

if [[ "${skip_tests}" == false ]]; then
    printf 'Running the demo test suite inside the WSL Conda environment...\n'
    "${conda_executable}" run --no-capture-output \
        --name "${environment_name}" \
        python -m unittest discover -s tests -v
    "${conda_executable}" run --no-capture-output \
        --name "${environment_name}" \
        python -m unittest discover -s demo/tests -v
fi

printf '\nReady. Launch with: ./scripts/launch_demo.sh\n'
