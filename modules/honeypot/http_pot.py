import socket
import threading
from datetime import datetime


class HTTPHoneypot:
    REPLY = (b"HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\n"
             b"Content-Type: text/html\r\nContent-Length: 9\r\n\r\nnot found")

    def __init__(self, db, on_alert, port=8080):
        self.db = db
        self.on_alert = on_alert
        self.port = port

    def handle(self, conn, addr):
        ip = addr[0]
        conn.settimeout(5)
        try:
            data = conn.recv(4096).decode(errors="replace")
            if data:
                first = data.splitlines()[0][:120]
                self.on_alert("honeypot", "medium", "honeypot_http_hit", ip,
                              {"request": first, "time": str(datetime.now())})
                conn.sendall(self.REPLY)
        except Exception:
            pass
        finally:
            conn.close()

    def start(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(20)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
