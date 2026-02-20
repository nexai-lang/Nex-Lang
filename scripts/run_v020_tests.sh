#!/usr/bin/env bash
set -e

BIN=./target/debug/nex

$BIN run examples/v020_cancel_kills_child.nex
$BIN run examples/v020_cancel_propagates_nested.nex
$BIN run examples/v020_autocleanup_parent_exit.nex
$BIN run examples/v020_join_waits_subtree.nex
$BIN run examples/v020_no_orphans.nex

echo "✅ v0.2.0 golden tests passed"
