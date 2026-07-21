#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Building frontend..."
cd dashboard
npm run build:embed
cd ..

echo "==> Building Rust backend..."
cargo build -p agentsight-local

echo "==> Done! Binary: target/debug/agentsight-local"
