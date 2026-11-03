import threading


class EventBus:
    """Chaque module publie ses alertes, les abonnés les consomment."""

    def __init__(self):
        self._subs = []
        self._lock = threading.Lock()

    def subscribe(self, fn):
        with self._lock:
            self._subs.append(fn)

    def publish(self, source, severity, event_type, src_ip, details):
        with self._lock:
            subscribers = list(self._subs)
        for fn in subscribers:
            try:
                fn(source, severity, event_type, src_ip, details)
            except Exception as exc:
                print(f"[bus] abonne en erreur: {exc}")
