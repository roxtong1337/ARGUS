#!/bin/bash
# REA demo: exercises the whole toolchain against a local stand-in for Hermes.
# Everything runs offline; no external service is contacted.
set -u

cd "$(dirname "$0")"
PY=${PYTHON:-python}
PORT=8971

echo "=============================================================="
echo " REA demo"
echo "=============================================================="

echo
echo "--- 1. rule pack validation -----------------------------------"
$PY -m rea.cli rules check rules/

echo
echo "--- 2. triage a malicious sample ------------------------------"
$PY -m rea.cli scan samples/malicious_sample.sh --quiet || true

echo
echo "--- 3. triage a benign sample (expect CLEAN) ------------------"
$PY -m rea.cli scan samples/benign_sample.sh --quiet || true

echo
echo "--- 4. batch triage a directory -------------------------------"
$PY -m rea.cli batch samples -o /tmp/rea_demo.jsonl --quiet 2>/dev/null || true
$PY - <<'PY'
import json
for line in open("/tmp/rea_demo.jsonl"):
    if not line.strip():
        continue
    r = json.loads(line)
    print(f"  {r['verdict']:10} score={r['risk_score']:3}  {r['basename']}")
PY

echo
echo "--- 5. start a local Hermes stand-in on port $PORT ------------"
$PY - <<'PY' &
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

OUT = "/tmp/rea_demo_received.json"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        with open(OUT, "w") as fh:
            json.dump(
                {
                    "path": self.path,
                    "apikey": self.headers.get("X-API-Key"),
                    "body": body,
                },
                fh,
                indent=2,
            )
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b'{"accepted":true}')

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8971), Handler).serve_forever()
PY
SERVER_PID=$!
sleep 1.5

echo
echo "--- 6. send the report to Hermes (detections mode) ------------"
$PY -m rea.cli send samples/malicious_sample.sh --to hermes --quiet \
    --set base_url="http://127.0.0.1:$PORT" \
    --set path=/api/v1/ingest \
    --set auth_style=apikey \
    --set api_key=demo-key \
    --set payload_mode=detections || true

echo
echo "--- 7. what Hermes received -----------------------------------"
$PY - <<'PY'
import json

d = json.load(open("/tmp/rea_demo_received.json"))
b = d["body"]
print(f"  POST {d['path']}  (X-API-Key: {d['apikey']})")
print(f"  source={b['source']}  events={len(b['events'])}")
e = b["events"][0]
print(f"  schema={e['schema']}  verdict={e['verdict']}  score={e['risk_score']}")
print(f"  sha256={e['artifact']['sha256']}")
print(f"  detection={e['detection']['id']} ({e['detection']['severity']})")
PY

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo
echo "--- 8. is detonation available? -------------------------------"
$PY -m rea.cli sandbox || echo "  (no container runtime: detonation is unavailable, which is a valid outcome)"

echo
echo "--- 9. detonate the sample in the sandbox ---------------------"
if $PY -m rea.cli sandbox >/dev/null 2>&1; then
    $PY -m rea.cli detonate samples/malicious_sample.sh --timeout 25 --quiet || true
else
    echo "  skipped: no container runtime. Static triage still produced a report,"
    echo "  and the runner refuses rather than executing the sample on the host."
fi

echo
echo "--- 10. the same investigation through the ARGUS agent --------"
$PY -m rea.cli agent --no-colour --exec "integrations" --exec "rules" --exec "scan samples/benign_sample.sh"

echo
echo "=============================================================="
echo " demo complete"
echo "=============================================================="
