import subprocess
import time
from pathlib import Path


class Shield:
    def __init__(self, db, on_alert):
        self.db = db
        self.on_alert = on_alert

    @staticmethod
    def _run(cmd):
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)

    def check_ssh_root_login(self):
        out = self._run("sshd -T 2>/dev/null | grep -i permitrootlogin").stdout.strip()
        return "no" in out.lower(), out or "sshd inaccessible", \
            "PermitRootLogin no dans /etc/ssh/sshd_config"

    def check_password_auth(self):
        out = self._run("sshd -T 2>/dev/null | grep -i passwordauthentication").stdout.strip()
        return "no" in out.lower(), out or "sshd inaccessible", \
            "PasswordAuthentication no (authentification par cles)"

    def check_ssh_port(self):
        out = self._run("sshd -T 2>/dev/null | grep -i '^port '").stdout.strip()
        return "22" not in out, out or "sshd inaccessible", \
            "Deplacer SSH vers un port non standard"

    def check_ip_forward(self):
        p = Path("/proc/sys/net/ipv4/ip_forward")
        val = p.read_text().strip() if p.exists() else "1"
        return val == "0", f"ip_forward={val}", "sysctl -w net.ipv4.ip_forward=0"

    def check_umask(self):
        out = self._run("grep -i umask /etc/login.defs").stdout.strip()
        return ("077" in out or "027" in out), out or "umask absent", \
            "UMASK 077 dans /etc/login.defs"

    def check_new_suid(self):
        out = self._run("find / -xdev -perm -4000 -mtime -7 2>/dev/null").stdout.strip()
        return not out, out[:500] or "aucun", "Verifier tout nouveau binaire SUID"

    def check_listening(self):
        out = self._run("ss -tulnp 2>/dev/null | grep LISTEN").stdout.strip()
        return True, out[:800], "Desactiver les services inutiles detectes"

    def audit(self):
        checks = {
            "ssh_root_login": self.check_ssh_root_login,
            "ssh_password_auth": self.check_password_auth,
            "ssh_port_default": self.check_ssh_port,
            "ip_forward": self.check_ip_forward,
            "umask_policy": self.check_umask,
            "new_suid_binaries": self.check_new_suid,
            "listening_services": self.check_listening,
        }
        result = {}
        for name, fn in checks.items():
            ok, detail, fix = fn()
            result[name] = ok
            self.db.insert_event("shield", "low" if ok else "medium", "cis_check", None,
                                 {"check": name, "ok": ok, "detail": detail, "fix": fix})
            if not ok:
                self.on_alert("shield", "medium", "hardening_gap", None,
                              {"check": name, "fix": fix})
        return result

    def run_forever(self, interval=21600):
        while True:
            self.audit()
            time.sleep(interval)
