import threading
import time
from collections import defaultdict, deque

from scapy.all import IP, TCP, sniff


class NetWatch:
    """Detection SYN flood et balayage de ports a partir du trafic TCP."""

    def __init__(self, db, on_alert, syn_threshold=100, portscan_threshold=15):
        self.db = db
        self.on_alert = on_alert
        self.syn_threshold = syn_threshold
        self.portscan_threshold = portscan_threshold
        self.syns = defaultdict(deque)
        self.ports = defaultdict(set)
        self.lock = threading.Lock()

    def _packet(self, pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        ip, tcp = pkt[IP], pkt[TCP]
        now = time.time()
        with self.lock:
            if tcp.flags != 0x02:
                return
            q = self.syns[ip.src]
            q.append(now)
            while q and now - q[0] > 10:
                q.popleft()
            self.ports[ip.src].add(tcp.dport)
            if len(q) > self.syn_threshold:
                self.on_alert("netwatch", "high", "syn_flood", ip.src,
                              {"rate_sps": len(q)})
                q.clear()
            if len(self.ports[ip.src]) > self.portscan_threshold:
                self.on_alert("netwatch", "medium", "port_scan", ip.src,
                              {"ports": sorted(self.ports[ip.src])[:50]})
                self.ports[ip.src].clear()

    def start(self, iface="eth0"):
        threading.Thread(
            target=sniff,
            kwargs={"iface": iface, "filter": "tcp", "prn": self._packet, "store": False},
            daemon=True,
        ).start()
