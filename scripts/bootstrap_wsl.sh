#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
miniforge_prefix="${MINIFORGE_PREFIX:-${HOME}/miniforge3}"
release_api_url="${MINIFORGE_RELEASE_API_URL:-https://api.github.com/repos/conda-forge/miniforge/releases/latest}"

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

if conda_executable="$(find_conda)"; then
    printf 'Using existing WSL Conda: %s\n' "${conda_executable}"
else
    if [[ "$(uname -s)" != "Linux" ]]; then
        printf 'This bootstrap script must run inside WSL/Linux.\n' >&2
        exit 1
    fi
    if [[ "$(uname -m)" != "x86_64" ]]; then
        printf 'This bootstrap currently supports x86_64 WSL only (found %s).\n' "$(uname -m)" >&2
        exit 1
    fi
    if [[ -e "${miniforge_prefix}" ]]; then
        printf 'Refusing to overwrite existing non-Conda path: %s\n' "${miniforge_prefix}" >&2
        exit 1
    fi
    command -v curl >/dev/null 2>&1 || {
        printf 'curl is required to install Miniforge.\n' >&2
        exit 1
    }
    command -v sha256sum >/dev/null 2>&1 || {
        printf 'sha256sum is required to verify Miniforge.\n' >&2
        exit 1
    }

    temporary_directory="$(mktemp -d)"
    trap 'rm -rf -- "${temporary_directory}"' EXIT
    release_metadata="${temporary_directory}/release.json"
    installer_path="${temporary_directory}/Miniforge3-Linux-x86_64.sh"
    checksum_path="${installer_path}.sha256"

    printf 'Resolving the current official conda-forge Miniforge release...\n'
    curl --fail --location --silent --show-error \
        --header 'Accept: application/vnd.github+json' \
        "${release_api_url}" \
        --output "${release_metadata}"
    mapfile -t release_assets < <(
        python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    release = json.load(stream)
assets = {item["name"]: item["browser_download_url"] for item in release.get("assets", [])}
tag = release.get("tag_name")
installer_name = f"Miniforge3-{tag}-Linux-x86_64.sh"
if installer_name not in assets:
    installer_name = "Miniforge3-Linux-x86_64.sh"
if installer_name not in assets or installer_name + ".sha256" not in assets:
    raise SystemExit("Could not resolve one installer/checksum pair from the release metadata.")
print(assets[installer_name])
print(assets[installer_name + ".sha256"])
' "${release_metadata}"
    )
    if [[ ${#release_assets[@]} -ne 2 ]]; then
        printf 'Could not resolve the Miniforge installer and checksum assets.\n' >&2
        exit 1
    fi

    printf 'Downloading checksum-verified Miniforge from the official release...\n'
    installer_url="${release_assets[0]}"
    checksum_url="${release_assets[1]}"
    curl --fail --location --silent --show-error "${installer_url}" --output "${installer_path}"
    curl --fail --location --silent --show-error "${checksum_url}" --output "${checksum_path}"

    expected_checksum="$(awk 'NR == 1 { print $1 }' "${checksum_path}")"
    actual_checksum="$(sha256sum "${installer_path}" | awk '{ print $1 }')"
    if [[ ! "${expected_checksum}" =~ ^[0-9a-fA-F]{64}$ ]] || \
       [[ "${actual_checksum,,}" != "${expected_checksum,,}" ]]; then
        printf 'Miniforge checksum verification failed.\n' >&2
        exit 1
    fi

    bash "${installer_path}" -b -p "${miniforge_prefix}"
    conda_executable="${miniforge_prefix}/bin/conda"
    printf 'Installed WSL-native Miniforge at %s\n' "${miniforge_prefix}"
fi

cd -- "${repository_root}"
CONDA_EXE="${conda_executable}" "${repository_root}/scripts/setup_demo.sh" "$@"
