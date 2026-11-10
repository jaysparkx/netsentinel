"""
"ميدان الهجوم" (Attack Range) — هجمات حقيقية على الجهاز نفسه لعرض الكشف الحي.

المشكلة: في قاعة العرض لا توجد هجمات حقيقية تحدث صدفة، فالكشف الحي سيُظهر
"لا شيء". الحل: ننشئ هدفاً ومهاجماً على نفس اللابتوب ونراقب بينهما:

    ┌────────────── اللابتوب (127.0.0.1 فقط) ──────────────┐
    │  خادم ويب "ضحية" :8088   ◄── تصفّح طبيعي (خلفية)        │
    │                          ◄── nmap / HTTP flood (أزرار) │
    │  NetSentinel يلتقط على lo0 ويحكم على كل اتصال          │
    └──────────────────────────────────────────────────────┘

🔒 الأمان: الهدف ثابت في الكود (127.0.0.1) ولا يمكن تغييره من الواجهة،
والخادم يقبل أوامر الهجوم فقط من الجهاز نفسه. لا تخرج أي حزمة إلى الشبكة.
"""

from __future__ import annotations

import logging
import random
import shutil
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

logger = logging.getLogger(__name__)

TARGET = "127.0.0.1"          # ثابت عمداً — لا يُقبل أي هدف آخر
VICTIM_PORT = 8088


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args) -> None:   # لا نريد سطراً في الطرفية لكل طلب
        pass


class _VictimServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        """
        تحت الإغراق يُغلق المهاجم الاتصال قبل أن يكمل الخادم الرد (BrokenPipe /
        ConnectionReset). هذا متوقّع تماماً، فلا نطبع لكل حالة تتبّع أخطاء مخيفاً.
        """
        import sys
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, TimeoutError)):
            super().handle_error(request, client_address)


def _find_nmap() -> str | None:
    # sudo يغيّر PATH أحياناً، فنبحث في مواقع Homebrew المعتادة أيضاً
    for candidate in (shutil.which("nmap"), "/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap"):
        if candidate and Path(candidate).exists():
            return candidate
    return None


@dataclass
class AttackInfo:
    id: str
    name: str
    description: str          # بالعربية — يظهر في الواجهة
    tool: str                 # الأداة الحقيقية المستخدمة
    expected: str             # ماذا نتوقّع أن يقول النظام


ATTACKS = {
    "port_scan": AttackInfo(
        "port_scan", "Port scan", "مسح 2001 منفذ لاكتشاف الخدمات المفتوحة — أول خطوة لأي مهاجم.",
        "nmap -sS -p 1-2000,8088", "Probe — المصنِّف يعرف هذا النمط من التدريب"),
    "service_scan": AttackInfo(
        "service_scan", "Service scan", "مسح أهم 100 منفذ مع محاولة معرفة البرنامج وإصداره على كل منفذ مفتوح.",
        "nmap -sT -sV --top-ports 100", "Probe أو Unknown-Anomaly"),
    "http_flood": AttackInfo(
        "http_flood", "HTTP flood", "3000 طلب ويب بـ 100 اتصال متوازٍ لإغراق الخادم — حجب خدمة على مستوى التطبيق.",
        "Python, 100 threads", "Unknown-Anomaly — لم يرَ المصنِّف هذا قط؛ يلتقطه كاشف الشذوذ"),
}


AUTO_SEQUENCE = ["port_scan", "http_flood", "service_scan"]   # ترتيب "وضع الهجوم" التلقائي
AUTO_PAUSE_SECONDS = 10
CONSOLE_LIMIT = 2000

HELP = [
    "available commands (this range only attacks 127.0.0.1):",
    "  scan            nmap port scan of ports 1-2000 + 8088",
    "  service-scan    nmap service/version detection on the top 100 ports",
    "  flood           HTTP flood: 3000 requests, 100 in parallel",
    "  auto on|off     attack mode: run scan, flood, service-scan in a loop",
    "  browse on|off   normal browsing traffic in the background",
    "  status          what is running now",
    "  clear           clear this screen",
]


@dataclass
class AttackRange:
    docroot: Path
    events: list[dict] = field(default_factory=list)
    console: list[dict] = field(default_factory=list)
    _victim: "_VictimServer | None" = None
    _background: threading.Event = field(default_factory=threading.Event)
    _auto: threading.Event = field(default_factory=threading.Event)
    _running: dict[str, threading.Thread] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------------ السجل وشاشة الطرفية
    def _log(self, kind: str, attack: str | None = None, **extra) -> None:
        with self._lock:
            self.events.append({"time": time.time(), "kind": kind, "attack": attack, **extra})

    def events_since(self, index: int) -> tuple[list[dict], int]:
        with self._lock:
            return self.events[index:], len(self.events)

    def say(self, text: str, stream: str = "out") -> None:
        """سطر في طرفية الموقع. stream: cmd (أمر)، out (مخرجات)، info، err."""
        with self._lock:
            self.console.append({"time": time.time(), "stream": stream, "text": text})
            if len(self.console) > CONSOLE_LIMIT:
                del self.console[: len(self.console) - CONSOLE_LIMIT]

    def console_since(self, index: int) -> tuple[list[dict], int]:
        """يُرجع الأسطر الجديدة. لو تجاوز index الطول (بعد قصّ السجل) نبدأ من آخر 200 سطر."""
        with self._lock:
            if index > len(self.console):
                index = max(0, len(self.console) - 200)
            return self.console[index:], len(self.console)

    # ------------------------------------------------------------------ الضحية
    def ensure_victim(self) -> None:
        """يشغّل خادم الويب الضحية مرة واحدة (في خيط خلفي)."""
        if self._victim is not None:
            return
        handler = partial(_QuietHandler, directory=str(self.docroot))
        self._victim = _VictimServer((TARGET, VICTIM_PORT), handler)
        threading.Thread(target=self._victim.serve_forever, daemon=True).start()
        self._log("victim_started", port=VICTIM_PORT)
        self.say(f"victim web server listening on {TARGET}:{VICTIM_PORT}", "info")

    def _get(self, path: str = "/", timeout: float = 2.0) -> bool:
        try:
            with urllib.request.urlopen(f"http://{TARGET}:{VICTIM_PORT}{path}", timeout=timeout) as resp:
                resp.read()
            return True
        except OSError:
            return False   # تحت الإغراق بعض الطلبات تفشل — هذا متوقّع

    # ------------------------------------------------------------------ حركة طبيعية
    def set_background(self, on: bool) -> None:
        """تصفّح "بشري" مستمر: طلب كل 0.3–1.5 ثانية لصفحات مختلفة."""
        self.ensure_victim()
        if on and not self._background.is_set():
            self._background.set()
            threading.Thread(target=self._browse, daemon=True).start()
            self._log("background_on")
            self.say("normal browsing started (1 request every 0.3-1.5 s)", "info")
        elif not on and self._background.is_set():
            self._background.clear()
            self._log("background_off")
            self.say("normal browsing stopped", "info")

    def _browse(self) -> None:
        pages = ["/", "/01_idea_and_problem.md", "/02_dataset.md", "/04_models_and_algorithms.md"]
        while self._background.is_set():
            self._get(random.choice(pages))
            time.sleep(random.uniform(0.3, 1.5))

    # ------------------------------------------------------------------ الهجمات
    def launch(self, attack_id: str, is_root: bool) -> dict:
        if attack_id not in ATTACKS:
            raise ValueError(f"Unknown attack '{attack_id}'")
        if self.is_running(attack_id):
            raise RuntimeError("هذا الهجوم يعمل حالياً")
        self.ensure_victim()
        runner = {"port_scan": self._port_scan, "service_scan": self._service_scan,
                  "http_flood": self._http_flood}[attack_id]
        thread = threading.Thread(target=self._run, args=(attack_id, runner, is_root), daemon=True)
        self._running[attack_id] = thread
        thread.start()
        return {"started": attack_id}

    def is_running(self, attack_id: str) -> bool:
        return attack_id in self._running and self._running[attack_id].is_alive()

    def _run(self, attack_id: str, runner, is_root: bool) -> None:
        self._log("attack_started", attack_id)
        start = time.time()
        try:
            detail = runner(is_root)
            seconds = round(time.time() - start, 1)
            self._log("attack_finished", attack_id, seconds=seconds, detail=detail)
            self.say(f"[{ATTACKS[attack_id].name}] finished in {seconds}s — {detail}", "info")
        except Exception as exc:   # نعرض الخطأ في الواجهة بدل أن يختفي بصمت
            logger.exception("attack %s failed", attack_id)
            self._log("attack_failed", attack_id, detail=str(exc))
            self.say(f"[{ATTACKS[attack_id].name}] failed: {exc}", "err")

    def _nmap(self, args: list[str]) -> str:
        """يشغّل nmap ويبثّ مخرجاته سطراً سطراً إلى طرفية الموقع."""
        nmap = _find_nmap()
        if nmap is None:
            raise RuntimeError("nmap غير مثبّت — brew install nmap")
        cmd = [nmap, *args, TARGET]
        self.say("nmap " + " ".join(args + [TARGET]), "cmd")
        open_ports = []
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.say(line)
                if "/tcp" in line and " open " in line:
                    open_ports.append(line.split("/")[0])
        return f"{len(open_ports)} open port(s): {', '.join(open_ports[:8])}" if open_ports else "no open ports"

    def _port_scan(self, is_root: bool) -> str:
        # SYN scan يحتاج root؛ بدونه نستخدم connect scan (نفس الهدف، أبطأ قليلاً)
        return self._nmap(["-sS" if is_root else "-sT", "-p", f"1-2000,{VICTIM_PORT}", "-T4", "-n"])

    def _service_scan(self, is_root: bool) -> str:
        return self._nmap(["-sT", "-sV", "--top-ports", "100", "-T4", "-n"])

    def _http_flood(self, is_root: bool, requests: int = 3000, workers: int = 100) -> str:
        self.say(f"flood http://{TARGET}:{VICTIM_PORT}/ --requests {requests} --threads {workers}", "cmd")
        done = {"ok": 0, "fail": 0}
        lock = threading.Lock()

        def hit(_):
            ok = self._get("/", timeout=2)
            with lock:
                done["ok" if ok else "fail"] += 1
                total = done["ok"] + done["fail"]
            if total % 500 == 0:
                self.say(f"  {total}/{requests} requests sent ({done['fail']} failed or timed out)")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(hit, range(requests)))
        return f"{done['ok']} of {requests} requests answered"

    # ------------------------------------------------------------------ وضع الهجوم التلقائي
    def set_auto(self, on: bool, is_root: bool) -> None:
        """عند التشغيل: هجوم ← توقّف 10 ث ← الهجوم التالي... حتى الإيقاف."""
        if on and not self._auto.is_set():
            self._auto.set()
            self._log("auto_on")
            self.say(f"attack mode ON — looping {', '.join(AUTO_SEQUENCE)} with {AUTO_PAUSE_SECONDS}s pauses", "info")
            threading.Thread(target=self._auto_loop, args=(is_root,), daemon=True).start()
        elif not on and self._auto.is_set():
            self._auto.clear()
            self._log("auto_off")
            self.say("attack mode OFF — the running attack will finish, no new ones start", "info")

    def _auto_loop(self, is_root: bool) -> None:
        step = 0
        while self._auto.is_set():
            attack_id = AUTO_SEQUENCE[step % len(AUTO_SEQUENCE)]
            step += 1
            if not self.is_running(attack_id):
                self.launch(attack_id, is_root)
            while self.is_running(attack_id):
                time.sleep(0.5)
            # توقّف بين الهجمات حتى يظهر الفرق بين "هجوم" و"هدوء" على الشريط
            for _ in range(AUTO_PAUSE_SECONDS * 2):
                if not self._auto.is_set():
                    return
                time.sleep(0.5)

    # ------------------------------------------------------------------ أوامر الطرفية
    def run_command(self, text: str, is_root: bool) -> None:
        """
        ينفّذ أمراً من طرفية الموقع. ⚠️ ليست طرفية حقيقية: نقبل فقط قائمة ثابتة
        من الأوامر. الخادم يعمل بصلاحيات root، وتنفيذ نصّ حرّ من صفحة ويب = ثغرة
        تنفيذ أوامر عن بُعد (RCE) — وهي بالضبط ما نُعلّمه في الأمن السيبراني.
        """
        text = " ".join(text.strip().split())[:80]
        self.say(text, "prompt")
        parts = text.lower().split()
        if not parts:
            return
        name, arg = parts[0], (parts[1] if len(parts) > 1 else "")
        attacks = {"scan": "port_scan", "nmap": "port_scan", "service-scan": "service_scan", "flood": "http_flood"}
        try:
            if name == "help":
                for line in HELP:
                    self.say(line, "info")
            elif name in attacks:
                self.launch(attacks[name], is_root)
            elif name == "auto" and arg in ("on", "off"):
                self.set_auto(arg == "on", is_root)
            elif name == "browse" and arg in ("on", "off"):
                self.set_background(arg == "on")
            elif name == "status":
                st = self.state()
                running = [a["name"] for a in st["attacks"] if a["running"]] or ["nothing"]
                self.say(f"running: {', '.join(running)} | attack mode: {'on' if st['auto'] else 'off'} | "
                         f"browsing: {'on' if st['background'] else 'off'}", "info")
            elif name == "clear":
                self.say("", "clear")
            else:
                self.say(f"command not allowed: {parts[0]} — type 'help'", "err")
        except (RuntimeError, ValueError) as exc:
            self.say(str(exc), "err")

    # ------------------------------------------------------------------ الحالة
    def state(self) -> dict:
        return {
            "target": f"{TARGET}:{VICTIM_PORT}",
            "victim": self._victim is not None,
            "background": self._background.is_set(),
            "auto": self._auto.is_set(),
            "nmap": _find_nmap() is not None,
            "attacks": [{**vars(a), "running": self.is_running(a.id)} for a in ATTACKS.values()],
        }
