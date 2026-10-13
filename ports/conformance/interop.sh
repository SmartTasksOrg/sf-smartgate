#!/usr/bin/env bash
# Start the Python SmartGate server on 127.0.0.1 with throw-away tokens and run every port's client
# against it (evaluate, block, start, remote kill reaching a checkpoint, idempotent second kill).
#   ports/conformance/interop.sh [node go rust java csharp php ruby]
set -u
cd "$(dirname "$0")/../.."
PORT=${SMARTGATE_INTEROP_PORT:-8719}
export SMARTGATE_URL="http://127.0.0.1:$PORT"
export SMARTGATE_AGENT_TOKEN="interop-agent-$RANDOM$RANDOM"
export SMARTGATE_OPERATOR_TOKEN="interop-operator-$RANDOM$RANDOM"
PY=${PYTHON:-python3}
PYTHONPATH=src "$PY" -m sf_smartgate.cli serve --port "$PORT" --kill-rate 1000 >/tmp/smartgate-interop.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for _ in $(seq 50); do curl -fs "$SMARTGATE_URL/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
want=("$@"); [ ${#want[@]} -eq 0 ] && want=(node go rust java csharp php ruby)
fail=0
run() {
  local name=$1 tool=$2; shift 2
  if ! command -v "$tool" >/dev/null 2>&1; then echo "$name: skipped ($tool not installed)"; return; fi
  if out=$("$@" 2>&1); then echo "$out" | grep -v '^Picked up' | tail -1; else echo "$out" | tail -20; echo "$name: FAILED"; fail=1; fi
}
for e in "${want[@]}"; do
  case $e in
    node) run node node node ports/node/test/interop.js ;;
    go) run go go bash -o pipefail -c "cd ports/go && go run ./cmd/interop" ;;
    rust) run rust cargo bash -o pipefail -c "cd ports/rust && cargo run --quiet --offline --bin interop" ;;
    java) run java javac bash -o pipefail -c "ports/java/build.sh && java -cp ports/java/build/classes cloud.smarttasks.smartgate.Interop" ;;
    csharp) run csharp dotnet bash -o pipefail -c "cd ports/csharp && dotnet run --project Interop 2>&1 | tail -1" ;;
    php) run php php php ports/php/bin/interop.php ;;
    ruby) run ruby ruby ruby ports/ruby/bin/interop.rb ;;
  esac
done
exit $fail
