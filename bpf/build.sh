#!/usr/bin/env bash
# Rebuilds every object under bpf/ with the clang lines in the header comment of each bpf/**/*.c.
set -euo pipefail
cd "$(dirname "$0")/.."

for src in bpf/*/*.c; do
    lines="$(awk '{ print } /\*\// { exit }' "$src" | grep -o 'clang -target bpf .*')" \
        || { echo "$src: no build line in its header" >&2; exit 1; }
    while read -r line; do
        echo "$line"
        $line
    done <<<"$lines"
done
