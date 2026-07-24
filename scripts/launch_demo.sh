#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
environment_name="${ROUTER_DUMP_ENV_NAME:-router-dump-analyzer-demo}"
bind_address="127.0.0.1"
port="8765"
open_browser=false
api_only=false
rebuild_fixture=false
full_scale=true
matched_event_target=125000
resource_target=10000

usage() {
    cat <<'EOF'
Usage: ./scripts/launch_demo.sh [options]

Options:
  --host ADDRESS       Bind address (default: 127.0.0.1)
  --port PORT          TCP port (default: 8765)
  --frontend-dir PATH  Frontend distribution (default: <repository>/frontend)
  --api-only           Disable integrated pages for split-process development
  --open-browser       Ask the demo process to open the browser
  --no-browser         Keep browser launch disabled (the WSL default)
  --rebuild-fixture    Regenerate the 125K-event / 10K-resource corpus and TGZ
  --review-projection  Load the small embedded review projection instead
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
        --review-projection)
            full_scale=false
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

if ! demo_python="$("${conda_executable}" run --name "${environment_name}" python -c 'import sys; print(sys.executable)' 2>/dev/null)"; then
    printf 'Conda environment %s is missing. Run ./scripts/setup_demo.sh first.\n' "${environment_name}" >&2
    exit 1
fi
demo_python="$(printf '%s\n' "${demo_python}" | tail -n 1)"
if [[ ! -x "${demo_python}" ]]; then
    printf 'Could not resolve the Python executable for Conda environment %s.\n' "${environment_name}" >&2
    exit 1
fi

# This packed archive is the single, hard-coded demo input requested for review.
fixture_argument="samples/generated-scale/router-state-lab-100k.tgz"
fixture_archive="${repository_root}/${fixture_argument}"
frontend_root="${frontend_root:-${repository_root}/frontend}"
scale_scenario="${repository_root}/samples/generated-scale/scenario.json"
review_manifest="${repository_root}/samples/generated/unpacked/node-a/manifest.json"
review_resources="${repository_root}/samples/generated/illustrative/resources.jsonl"

cd -- "${repository_root}"
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

if [[ "${api_only}" == false && ! -f "${frontend_root}/frontend-manifest.json" ]]; then
    printf 'Frontend distribution is incomplete: %s/frontend-manifest.json was not found.\n' \
        "${frontend_root}" >&2
    exit 1
fi

scale_ready=false
if [[ -f "${scale_scenario}" ]] && \
   "${demo_python}" -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    scenario = json.load(stream)
scale = scenario.get("scale", {})
ready = (
    scenario.get("scenario_id") == "evpn-multihome-mass-failover-v2"
    and int(scenario.get("generator_version", 0)) >= 7
    and int(scale.get("events", 0)) >= int(sys.argv[2])
    and int(scale.get("resources", 0)) == int(sys.argv[3])
)
raise SystemExit(0 if ready else 1)
' "${scale_scenario}" "${matched_event_target}" "${resource_target}"; then
    scale_ready=true
fi

scale_rebuilt=false
if [[ "${rebuild_fixture}" == true || "${scale_ready}" == false ]]; then
    printf 'Generating the deterministic %d matched-event EVPN scale corpus...\n' "${matched_event_target}"
    "${demo_python}" scripts/generate_scale_fixtures.py \
        --events "${matched_event_target}" \
        --resources "${resource_target}"
    scale_rebuilt=true
fi

if [[ "${rebuild_fixture}" == true || ! -f "${review_manifest}" || ! -f "${review_resources}" ]]; then
    printf 'Generating the browser-sized review projection...\n'
    "${demo_python}" scripts/generate_sample_bundle.py
fi

pack_ready=false
if [[ -f "${fixture_archive}" ]] && \
   "${demo_python}" scripts/validate_scale_archive.py \
      "${fixture_archive}" "${matched_event_target}" "${resource_target}" 7; then
    pack_ready=true
fi

if [[ "${rebuild_fixture}" == true || "${scale_rebuilt}" == true || "${pack_ready}" == false ]]; then
    printf 'Packing CTF logs and heterogeneous resource tables into one TGZ...\n'
    "${demo_python}" scripts/generate_packed_scale_bundle.py \
        --output "${fixture_argument}"
fi

demo_arguments=(
    -m router_dump_analyzer.demo_app
    --host "${bind_address}"
    --port "${port}"
    --frontend-dir "${frontend_root}"
    --fixture-archive "${fixture_argument}"
)
if [[ "${api_only}" == true ]]; then
    demo_arguments+=(--api-only)
fi
if [[ "${full_scale}" == true ]]; then
    demo_arguments+=(--full-scale)
fi
if [[ "${open_browser}" == true ]]; then
    demo_arguments+=(--open-browser)
fi

printf 'Using packed fixture: %s\n' "${fixture_archive}"
if [[ "${full_scale}" == true ]]; then
    printf 'Loading the complete %d-matched-event / %d-resource normalized corpus.\n' \
        "${matched_event_target}" "${resource_target}"
else
    printf 'Loading the embedded browser review projection.\n'
fi
if [[ "${api_only}" == true ]]; then
    printf 'Starting Router State Lab backend API at http://%s:%s\n' \
        "${bind_address}" "${port}"
    printf "Run 'npm --prefix frontend run serve -- --backend http://%s:%s' in another terminal for the split frontend.\n" \
        "${bind_address}" "${port}"
else
    printf 'Starting Router State Lab at http://%s:%s\n' "${bind_address}" "${port}"
fi
exec "${demo_python}" "${demo_arguments[@]}"
