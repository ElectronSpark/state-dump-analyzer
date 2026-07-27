#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
environment_name="${ROUTER_DUMP_ENV_NAME:-router-dump-analyzer-demo}"
bind_address="127.0.0.1"
port="8765"
open_browser=false
api_only=false
rebuild_fixture=false
validate_fixture=false

usage() {
    cat <<'EOF'
Usage: ./scripts/launch_demo.sh [options]

Options:
  --host ADDRESS       Bind address (default: 127.0.0.1)
  --port PORT          TCP port (default: 8765)
  --frontend-dir PATH  Frontend distribution (default: <repository>/frontend)
  --api-only           Disable integrated pages for split-process development
  --open-browser       Ask the core analyzer process to open the browser
  --no-browser         Keep browser launch disabled (the WSL default)
  --rebuild-fixture    Regenerate the complete multi-node demo assembly
  --validate-fixture   Fully validate an existing generated assembly
  -h, --help           Show this help
EOF
}

while (($#)); do
    case "$1" in
        --host)
            [[ $# -ge 2 ]] || { printf '%s\n' '--host requires a value.' >&2; exit 2; }
            bind_address="$2"
            shift
            ;;
        --port)
            [[ $# -ge 2 ]] || { printf '%s\n' '--port requires a value.' >&2; exit 2; }
            port="$2"
            shift
            ;;
        --frontend-dir)
            [[ $# -ge 2 ]] || { printf '%s\n' '--frontend-dir requires a value.' >&2; exit 2; }
            frontend_root="$2"
            shift
            ;;
        --api-only)
            api_only=true
            ;;
        --open-browser)
            open_browser=true
            ;;
        --no-browser)
            open_browser=false
            ;;
        --rebuild-fixture)
            rebuild_fixture=true
            ;;
        --validate-fixture)
            validate_fixture=true
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

if [[ ! "${port}" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    printf 'Port must be an integer from 1 through 65535.\n' >&2
    exit 2
fi

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

if ! analyzer_python="$("${conda_executable}" run --name "${environment_name}" python -c 'import sys; print(sys.executable)' 2>/dev/null)"; then
    printf 'Conda environment %s is missing. Run ./scripts/setup_demo.sh first.\n' "${environment_name}" >&2
    exit 1
fi
analyzer_python="$(printf '%s\n' "${analyzer_python}" | tail -n 1)"
if [[ ! -x "${analyzer_python}" ]]; then
    printf 'Could not resolve the Python executable for Conda environment %s.\n' "${environment_name}" >&2
    exit 1
fi

# This generated assembly is the one input for both node and fabric views.
fixture_argument="demo/fixtures/router-state-lab-demo.tgz"
fixture_archive="${repository_root}/${fixture_argument}"
frontend_root="${frontend_root:-${repository_root}/frontend}"

cd -- "${repository_root}"
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

if [[ "${api_only}" == false && ! -f "${frontend_root}/frontend-manifest.json" ]]; then
    printf 'Frontend distribution is incomplete: %s/frontend-manifest.json was not found.\n' \
        "${frontend_root}" >&2
    exit 1
fi

printf '%s\n' \
    '[fixture] Ensuring the canonical full-scale multi-node assembly...'
ensure_arguments=(
    -m rsl_demo_generator
    --ensure-launchable "${fixture_archive}"
    --path-only
)
if [[ "${rebuild_fixture}" == true ]]; then
    ensure_arguments+=(--force-rebuild)
fi
ensure_started="${SECONDS}"
if ! selected_fixture="$(
    "${analyzer_python}" "${ensure_arguments[@]}"
)"; then
    printf '%s\n' \
        'Could not prepare the full-scale multi-node fixture.' >&2
    exit 1
fi
selected_fixture="$(printf '%s\n' "${selected_fixture}" | tail -n 1)"
if [[ -z "${selected_fixture}" || ! -f "${selected_fixture}" ]]; then
    printf '%s\n' \
        'Generator did not return a regular launch fixture path.' >&2
    exit 1
fi
printf '[fixture] Launch input ready in %d s: %s\n' \
    "$((SECONDS - ensure_started))" "${selected_fixture}"

if [[ "${validate_fixture}" == true ]]; then
    printf '%s\n' '[fixture] Validating the existing generated assembly...'
    validation_started="${SECONDS}"
    "${analyzer_python}" -m rsl_demo_generator \
        --validate "${selected_fixture}"
    printf '[fixture] Validation finished in %d s.\n' \
        "$((SECONDS - validation_started))"
fi

core_arguments=(
    -m router_dump_analyzer
    --plugin demo_router
    --input "${selected_fixture}"
    --host "${bind_address}"
    --port "${port}"
    --frontend-dir "${frontend_root}"
)
if [[ "${api_only}" == true ]]; then
    core_arguments+=(--api-only)
fi
if [[ "${open_browser}" == false ]]; then
    core_arguments+=(--no-browser)
fi

printf 'Using generated assembly: %s\n' "${selected_fixture}"
printf '%s\n' 'Single-node and fabric views read this same generated assembly.'
if [[ "${api_only}" == true ]]; then
    printf 'Starting Router State Lab backend API at http://%s:%s\n' \
        "${bind_address}" "${port}"
    printf "Run 'npm --prefix frontend run serve -- --backend http://%s:%s' in another terminal for the split frontend.\n" \
        "${bind_address}" "${port}"
else
    printf 'Starting Router State Lab at http://%s:%s\n' "${bind_address}" "${port}"
fi
printf '%s\n' \
    'The server intentionally stays attached to this terminal. Press Ctrl+C to stop it.'
exec "${analyzer_python}" "${core_arguments[@]}"
