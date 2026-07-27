#!/usr/bin/env sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment_name=state-dump-generator
bind_address=127.0.0.1
port=8770
open_browser=
refresh_environment=

usage() {
    echo "Usage: ./launch.sh [--host ADDRESS] [--port PORT] [--open] [--refresh-environment]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --host)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            bind_address=$2
            shift 2
            ;;
        --port)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            port=$2
            shift 2
            ;;
        --open)
            open_browser=1
            shift
            ;;
        --refresh-environment)
            refresh_environment=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

command -v conda >/dev/null 2>&1 || {
    echo "Conda was not found. Install Miniconda or Miniforge, then reopen this shell." >&2
    exit 1
}

cd "$project_root"
if ! conda run -n "$environment_name" python -c "import state_dump_generator" >/dev/null 2>&1; then
    echo "Creating Conda environment '$environment_name'..."
    conda env create --file environment.yml
elif [ -n "$refresh_environment" ]; then
    echo "Updating Conda environment '$environment_name'..."
    conda env update --name "$environment_name" --file environment.yml --prune
fi

set -- conda run --no-capture-output -n "$environment_name" \
    state-dump-generator serve --host "$bind_address" --port "$port"
if [ -n "$open_browser" ]; then
    set -- "$@" --open
fi
exec "$@"

