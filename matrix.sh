#!/usr/bin/env bash
# Run the bundled Node.js October 2026 regression harness against pinned Node images.
# Usage: ./matrix.sh [22.23.3 22.23.4 24.22.0 24.22.1 26.12.0 26.12.1]
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
evidence_dir=${EVIDENCE_DIR:-"$script_dir/evidence"}
mkdir -p "$evidence_dir"
if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Docker not found. Invoke node probe.mjs directly in a disposable environment.' >&2
  exit 1
fi
if (($#)); then versions=("$@"); else versions=(22.23.3 22.23.4 24.22.0 24.22.1 26.12.0 26.12.1); fi
for version in "${versions[@]}"; do
  [[ "$version" =~ ^(22|24|26)\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid version: $version" >&2; exit 1; }
  image="node:$version"
  echo "== $image =="
  file="$evidence_dir/node-$version.json"
  rc=0
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=128m,mode=1777 \
    --memory 512m --pids-limit 128 \
    -v "$script_dir:/harness:ro" "$image" \
    node /harness/probe.mjs --json > "$file" || rc=$?
  if [[ $rc == 0 || $rc == 2 ]]; then
    node --input-type=module - "$file" <<'JS'
import {readFileSync} from 'node:fs';
const r=JSON.parse(readFileSync(process.argv[2],'utf8'));
const vulnerable=r.checks.filter(x=>x.outcome==='vulnerable-behavior');
const inconclusive=r.checks.filter(x=>x.outcome==='inconclusive');
console.log(`${r.node} ${r.versionStatus}: ${vulnerable.length} vulnerable observations, ${inconclusive.length} inconclusive`);
for(const c of vulnerable) console.log(`  ${c.cve} ${c.probe}`);
JS
  else
    echo "ERROR: harness execution failed rc=$rc; evidence may be incomplete: $file" >&2
    exit "$rc"
  fi
  echo "Saved: $file"
done
