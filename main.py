import signal
import sys
import threading
import time

from core.bus import EventBus
from core.config import CONFIG
from core.database import Database
from modules.dashboard import app as dashboard
from modules.honeypot.http_pot import HTTPHoneypot
from modules.honeypot.ssh_pot import SSHHoneypot
from modules.logfire.correlator import Correlator
from modules.netwatch.detector import NetWatch
from modules.responder.responder import Responder
from modules.sentinel.sentinel import Sentinel
from modules.shield.hardening import Shield
from modules.vulnscan.scanner import VulnScan


def main():
    db = Database(CONFIG.get("logfire.db_path", "data/events.db"))
    bus = EventBus()

    def pipeline(source, severity, event_type, src_ip, details):
        bus.publish(source, severity, event_type, src_ip, details)

    responder = Responder(
        db,
        block_threshold=CONFIG.get("responder.auto_block_threshold", 10),
        block_minutes=CONFIG.get("responder.block_duration_minutes", 30),
    )
    bus.subscribe(responder.feed)
    bus.subscribe(lambda s, sev, t, ip, d: db.insert_event(s, sev, t, ip, d))
    bus.subscribe(dashboard.push_alert)

    netwatch = NetWatch(db, pipeline,
                        syn_threshold=CONFIG.get("netwatch.syn_flood_threshold", 100),
                        portscan_threshold=CONFIG.get("netwatch.portscan_threshold", 15))
    sentinel = Sentinel(db, pipeline,
                        watch_paths=CONFIG.get("sentinel.watch_paths", ["/etc"]),
                        interval=CONFIG.get("sentinel.interval", 60))
    ssh_pot = SSHHoneypot(db, pipeline, port=CONFIG.get("honeypot.ssh_port", 2222))
    http_pot = HTTPHoneypot(db, pipeline, port=CONFIG.get("honeypot.http_port", 8080))
    correlator = Correlator(db, pipeline)
    shield = Shield(db, pipeline)
    vulnscan = VulnScan(db, pipeline)

    if not sentinel.baseline:
        print("[404SECURITY] construction de la baseline d'integrite...")
        sentinel.build_baseline()

    iface = CONFIG.get("netwatch.interface", "eth0")
    workers = [
        threading.Thread(target=netwatch.start, args=(iface,), daemon=True),
        threading.Thread(target=sentinel.run_forever, daemon=True),
        threading.Thread(target=ssh_pot.start, daemon=True),
        threading.Thread(target=http_pot.start, daemon=True),
        threading.Thread(target=correlator.run_forever, daemon=True),
        threading.Thread(target=shield.run_forever, daemon=True),
        threading.Thread(target=vulnscan.run_forever, daemon=True),
        threading.Thread(target=responder.unblock_expired, daemon=True),
    ]
    for w in workers:
        w.start()

    host = CONFIG.get("dashboard.listen", "0.0.0.0")
    port = CONFIG.get("dashboard.port", 8443)
    print(f"[404SECURITY] socle actif - console : https://{host}:{port}")

    import uvicorn
    uvicorn.run(dashboard.app, host=host, port=port,
                ssl_certfile="certs/server.pem", ssl_keyfile="certs/server.pem")

    signal.signal(signal.SIGINT, lambda *_: (print("[404SECURITY] arret"), sys.exit(0)))
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
