#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Building agentsight-local frontend..."
cd dashboard
npm run build:embed
cd ..

echo "==> Building agentsight binary..."
cargo build --release

echo "==> Done! Binary: target/release/agentsight"
