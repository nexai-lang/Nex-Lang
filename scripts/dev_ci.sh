#!/usr/bin/env bash
set -euo pipefail

cargo build

BIN="./target/debug/nex"

echo "== Golden verification suite =="

shopt -s nullglob
for t in tests/golden/*.nex; do
  echo "-- verify-golden: $t"
  $BIN verify-golden "$t"
  echo "-- test-tamper: $t"
  $BIN test-tamper "$t" --trials 10
done

echo "✅ All golden + tamper checks passed"