#!/usr/bin/env bash
# Run the Redis failure test (needs Docker). Results: deploy/failure/out/*.json and metrics.txt.
set -euo pipefail
cd "$(dirname "$0")"
: "${SMARTGATE_AGENT_TOKEN:?set it}" "${SMARTGATE_OPERATOR_TOKEN:?set it}"
mkdir -p out
docker compose up -d --build redis gate-a gate-b
sleep 5
for g in gate-a gate-b; do
  docker compose run --rm -d --name "k6-$g" k6 run -e SMARTGATE_URL="http://$g:8711" -e RATE=${RATE:-500} -e DURATION=90s \
    --summary-export="/out/$g.json" /scripts/smartgate.js >/dev/null
done
sleep 30; echo "stopping redis"; docker compose stop redis
sleep 20; echo "starting redis"; docker compose start redis
sleep 50
for g in gate-a gate-b; do docker wait "k6-$g" >/dev/null 2>&1 || true; done
docker compose exec -T gate-a python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8711/metrics').read().decode())" > out/metrics.txt
python3 ../k6/merge.py out/gate-a.json out/gate-b.json | tee out/report.json
docker compose down
