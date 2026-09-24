#!/usr/bin/env bash
# Runs jarvisd with the development setup (creating it on first use).
set -euo pipefail

cd "$(dirname "$0")/.."
[[ -f .dev/config/daemon.toml ]] || scripts/dev-setup.sh

export JARVISD_LOG_FORMAT="${JARVISD_LOG_FORMAT:-pretty}"
exec cargo run --quiet -p jarvis-daemon --bin jarvisd -- --config "$(pwd)/.dev/config/daemon.toml" serve
