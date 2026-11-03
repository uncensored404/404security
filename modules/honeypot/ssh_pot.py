import socket
import threading
from datetime import datetime


class SSHHoneypot:
    BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

    def __init__(self, db, on_alert, port=2222):
        self.db = db
        self.on_alert = on_alert
        self.port = port

    def handle(self, conn, addr):
        ip = addr[0]
        self.on_alert("honeypot", "high", "ssh_connection", ip,
                      {"time": str(datetime.now())})
        try:
            conn.sendall(self.BANNER)
            conn.settimeout(15)
            conn.recv(1024)
            conn.sendall(b"\r\nPassword: ")
            while True:
                data = conn.recv(256)
                if not data:
                    break
                self.db.insert_event("honeypot", "medium", "ssh_input", ip,
                                     {"data": data.decode(errors="replace")[:100]})
        except Exception:
            pass
        finally:
            conn.close()

    def start(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(10)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
