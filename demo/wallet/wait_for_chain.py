"""Block until the demo chain has finished deploying, then exit 0.

Runs in the Transaction Service indexer before its normal start script. The
indexer's `setup_service` registers the Safe singletons only if their code is
already on the chain; started too early, it registers none and never indexes the
demo Safe. `docker compose up` orders this through depends_on, but
`docker compose restart` starts every container at once, so the indexer waits
here for the chain container's API, which answers only after the demo Safe,
Guard and Safe contracts are deployed. Stdlib only.
"""
import sys
import time
import urllib.request

URL = "http://chain:8080/api/state"
DEADLINE = time.time() + 600

while True:
    try:
        with urllib.request.urlopen(URL, timeout=5) as resp:
            if resp.status == 200:
                print("chain ready", flush=True)
                sys.exit(0)
    except Exception:  # noqa: BLE001 - not up yet
        pass
    if time.time() > DEADLINE:
        sys.exit("chain did not come up within 10 minutes")
    time.sleep(2)
