#!/bin/sh
# Entrypoint for the ai-cline-coder image.
#
# Exports API keys that were baked in at BUILD time (via --build-arg), but
# only when the variable is not already set in the container environment.
# This means runtime values passed with `docker run -e KEY=...` or
# `--env-file` always take precedence over build-time keys.
set -eu

BUILD_KEYS_FILE="/etc/cline/build-keys.env"

if [ -f "$BUILD_KEYS_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip blank lines and comments
        case "$line" in
            ''|'#'*) continue ;;
        esac

        key="${line%%=*}"
        value="${line#*=}"

        # Only export if not already provided at runtime
        eval "current=\${$key:-}"
        if [ -z "$current" ]; then
            export "$key=$value"
        fi
    done < "$BUILD_KEYS_FILE"
fi

exec "$@"