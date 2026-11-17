# Attack range for the live demo: a small victim web server plus real attacks
# (nmap and an HTTP flood), all against 127.0.0.1 only. The target can't be changed.

import random
import shutil
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TARGET = "127.0.0.1"
VICTIM_PORT = 8088

ATTACKS = {
    "port_scan": {"name": "Port scan", "tool": "nmap -sS -p 1-2000,8088"},
    "service_scan": {"name": "Service scan", "tool": "nmap -sT -sV --top-ports 100"},
    "http_flood": {"name": "HTTP flood", "tool": "3000 requests, 100 threads"},
}
AUTO_ORDER = ["port_scan", "http_flood", "service_scan"]

HELP = """commands (target is always 127.0.0.1):
  scan            nmap port scan
  service-scan    nmap service/version scan
  flood           HTTP flood
  auto on|off     repeat the attacks
  browse on|off   normal browsing in the background
  status          what is running
  clear           clear the screen"""


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class VictimServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # the flood closes connections early, that's expected
        import sys
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, TimeoutError)):
            super().handle_error(request, client_address)


def find_nmap():
    # sudo can change PATH, so also look in the homebrew folders
    for path in (shutil.which("nmap"), "/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap"):
        if path and Path(path).exists():
            return path
    return None


class AttackRange:
    def __init__(self, docroot):
        self.docroot = docroot
        self.lines = []          # what the terminal on the page shows
        self.lock = threading.Lock()
        self.victim = None
        self.browsing = threading.Event()
        self.auto = threading.Event()
        self.threads = {}

    def say(self, text, kind="out"):
        with self.lock:
            self.lines.append({"kind": kind, "text": text})
            if len(self.lines) > 2000:
                del self.lines[:500]

    def lines_since(self, index):
        with self.lock:
            if index > len(self.lines):
                index = max(0, len(self.lines) - 200)
            return self.lines[index:], len(self.lines)

    def start_victim(self):
        if self.victim:
            return
        handler = partial(QuietHandler, directory=str(self.docroot))
        self.victim = VictimServer((TARGET, VICTIM_PORT), handler)
        threading.Thread(target=self.victim.serve_forever, daemon=True).start()
        self.say(f"victim web server on {TARGET}:{VICTIM_PORT}", "info")

    def get(self, path="/", timeout=2.0):
        try:
            with urllib.request.urlopen(f"http://{TARGET}:{VICTIM_PORT}{path}", timeout=timeout) as r:
                r.read()
            return True
        except OSError:
            return False

    # normal traffic
    def set_browsing(self, on):
        self.start_victim()
        if on and not self.browsing.is_set():
            self.browsing.set()
            threading.Thread(target=self._browse, daemon=True).start()
            self.say("normal browsing on", "info")
        elif not on and self.browsing.is_set():
            self.browsing.clear()
            self.say("normal browsing off", "info")

    def _browse(self):
        pages = ["/", "/01_idea_and_problem.md", "/02_dataset.md", "/04_models_and_algorithms.md"]
        while self.browsing.is_set():
            self.get(random.choice(pages))
            time.sleep(random.uniform(0.3, 1.5))

    # attacks
    def running(self, attack):
        t = self.threads.get(attack)
        return t is not None and t.is_alive()

    def launch(self, attack, is_root):
        if attack not in ATTACKS:
            raise ValueError(f"unknown attack {attack}")
        if self.running(attack):
            raise RuntimeError(f"{attack} is already running")
        self.start_victim()
        t = threading.Thread(target=self._run, args=(attack, is_root), daemon=True)
        self.threads[attack] = t
        t.start()

    def _run(self, attack, is_root):
        start = time.time()
        try:
            if attack == "port_scan":
                # -sS needs root, -sT works without it
                result = self._nmap(["-sS" if is_root else "-sT", "-p", f"1-2000,{VICTIM_PORT}", "-T4", "-n"])
            elif attack == "service_scan":
                result = self._nmap(["-sT", "-sV", "--top-ports", "100", "-T4", "-n"])
            else:
                result = self._flood()
            self.say(f"{ATTACKS[attack]['name']} done in {time.time() - start:.1f}s, {result}", "info")
        except Exception as e:
            self.say(f"{ATTACKS[attack]['name']} failed: {e}", "err")

    def _nmap(self, args):
        nmap = find_nmap()
        if not nmap:
            raise RuntimeError("nmap is not installed (brew install nmap)")
        self.say("nmap " + " ".join(args + [TARGET]), "cmd")
        open_ports = []
        proc = subprocess.Popen([nmap, *args, TARGET], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                self.say(line)
            if "/tcp" in line and " open " in line:
                open_ports.append(line.split("/")[0])
        proc.wait()
        return f"{len(open_ports)} open port(s) {' '.join(open_ports)}"

    def _flood(self, total=3000, workers=100):
        self.say(f"flood http://{TARGET}:{VICTIM_PORT}/ ({total} requests, {workers} threads)", "cmd")
        counts = {"ok": 0, "fail": 0}
        lock = threading.Lock()

        def hit(_):
            ok = self.get("/", timeout=2)
            with lock:
                counts["ok" if ok else "fail"] += 1
                sent = counts["ok"] + counts["fail"]
            if sent % 500 == 0:
                self.say(f"  {sent}/{total} sent")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(hit, range(total)))
        return f"{counts['ok']}/{total} answered"

    # attack mode: scan, flood, service scan, repeat until turned off
    def set_auto(self, on, is_root):
        if on and not self.auto.is_set():
            self.auto.set()
            self.say("attack mode on", "info")
            threading.Thread(target=self._auto_loop, args=(is_root,), daemon=True).start()
        elif not on and self.auto.is_set():
            self.auto.clear()
            self.say("attack mode off", "info")

    def _auto_loop(self, is_root):
        i = 0
        while self.auto.is_set():
            attack = AUTO_ORDER[i % len(AUTO_ORDER)]
            i += 1
            if not self.running(attack):
                self.launch(attack, is_root)
            while self.running(attack):
                time.sleep(0.5)
            for _ in range(20):  # 10 second pause
                if not self.auto.is_set():
                    return
                time.sleep(0.5)

    def run_command(self, text, is_root):
        # only these commands, never run what the user typed (server is root)
        text = " ".join(text.split())[:80]
        self.say(text, "prompt")
        parts = text.lower().split()
        if not parts:
            return
        cmd = parts[0]
        arg = parts[1] if len(parts) > 1 else ""
        attacks = {"scan": "port_scan", "nmap": "port_scan", "service-scan": "service_scan", "flood": "http_flood"}
        try:
            if cmd == "help":
                for line in HELP.splitlines():
                    self.say(line, "info")
            elif cmd in attacks:
                self.launch(attacks[cmd], is_root)
            elif cmd == "auto" and arg in ("on", "off"):
                self.set_auto(arg == "on", is_root)
            elif cmd == "browse" and arg in ("on", "off"):
                self.set_browsing(arg == "on")
            elif cmd == "status":
                busy = [a["name"] for k, a in ATTACKS.items() if self.running(k)] or ["nothing"]
                self.say(f"running: {', '.join(busy)}, attack mode: {self.auto.is_set()}, "
                         f"browsing: {self.browsing.is_set()}", "info")
            elif cmd == "clear":
                self.say("", "clear")
            else:
                self.say(f"command not allowed: {cmd} (type help)", "err")
        except (RuntimeError, ValueError) as e:
            self.say(str(e), "err")

    def state(self):
        return {
            "browsing": self.browsing.is_set(),
            "auto": self.auto.is_set(),
            "nmap": find_nmap() is not None,
            "running": [k for k in ATTACKS if self.running(k)],
        }
