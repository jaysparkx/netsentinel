"""
مخطّط بيانات NSL-KDD: أسماء الأعمدة، مجموعات الميزات، وتصنيف الهجمات.

كل سجلّ (سطر) في NSL-KDD يمثّل "اتصالاً" (Connection) واحداً بين جهازين،
موصوفاً بـ 41 ميزة + اسم الهجوم + درجة الصعوبة.

الميزات مقسّمة إلى 4 مجموعات (وهذا التقسيم مهمّ لفهم المشروع):
    1. BASIC        : من ترويسة الاتصال نفسه (المدة، البروتوكول، البايتات...).
    2. CONTENT      : من محتوى الحزم (محاولات دخول فاشلة، صلاحيات root...).
                      → تحتاج فحص الحمولة (Deep Packet Inspection).
    3. TIME_TRAFFIC : إحصائيات آخر ثانيتين لنفس الجهاز الهدف.
    4. HOST_TRAFFIC : إحصائيات نافذة من آخر الاتصالات لنفس الجهاز الهدف (القيم حتى 255).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# أسماء الأعمدة بالترتيب الموجود في الملفات الخام
# ---------------------------------------------------------------------------
BASIC_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent",
]
CONTENT_FEATURES = [
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
]
TIME_TRAFFIC_FEATURES = [
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
]
HOST_TRAFFIC_FEATURES = [
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

ALL_FEATURES = BASIC_FEATURES + CONTENT_FEATURES + TIME_TRAFFIC_FEATURES + HOST_TRAFFIC_FEATURES
RAW_COLUMNS = ALL_FEATURES + ["attack", "difficulty"]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

# ميزات قيمتها ثابتة (صفر دائماً) في NSL-KDD → لا تحمل أي معلومة، نحذفها.
CONSTANT_FEATURES = ["num_outbound_cmds"]

# ميزات ذات توزيع "ذيل طويل" (قيم صغيرة غالباً وقيم ضخمة نادراً).
# نطبّق عليها log(1+x) لتقليص الفروقات الهائلة قبل التطبيع.
SKEWED_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "hot", "num_compromised", "num_root",
    "num_file_creations", "num_access_files", "count", "srv_count",
    "dst_host_count", "dst_host_srv_count", "wrong_fragment", "urgent",
    "num_failed_logins", "num_shells",
]

# ---------------------------------------------------------------------------
# ملفّات الميزات (Feature Profiles)
# ---------------------------------------------------------------------------
# "full": كل الميزات المفيدة — أعلى دقة لكن تتطلّب فحص المحتوى.
# "live": فقط ما يمكن حسابه من ترويسات الحزم (IP/TCP/UDP/ICMP) —
#         أي ما يستطيع وحدة الالتقاط الحي (live/flow.py) حسابه فعلياً.
FEATURE_PROFILES: dict[str, list[str]] = {
    "full": [f for f in ALL_FEATURES if f not in CONSTANT_FEATURES],
    "live": BASIC_FEATURES + TIME_TRAFFIC_FEATURES + HOST_TRAFFIC_FEATURES,
}

# ---------------------------------------------------------------------------
# تصنيف الهجمات: اسم الهجوم → الفئة الرئيسية
# ---------------------------------------------------------------------------
NORMAL_LABEL = "normal"
CLASS_NAMES = ["normal", "DoS", "Probe", "R2L", "U2R"]

ATTACK_CATEGORY: dict[str, str] = {
    # DoS — حجب الخدمة: إغراق الهدف حتى يعجز عن خدمة المستخدمين
    **dict.fromkeys(
        ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
         "udpstorm", "processtable", "worm", "mailbomb"], "DoS"),
    # Probe — الاستطلاع: مسح الشبكة بحثاً عن أجهزة ومنافذ وثغرات
    **dict.fromkeys(
        ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"], "Probe"),
    # R2L — من بعيد إلى محلي: مهاجم خارجي يحاول الحصول على حساب على الجهاز
    **dict.fromkeys(
        ["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
         "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack",
         "httptunnel", "sendmail", "named"], "R2L"),
    # U2R — من مستخدم إلى root: مستخدم عادي يحاول رفع صلاحياته
    **dict.fromkeys(
        ["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
         "xterm", "ps"], "U2R"),
}


def attack_to_category(attack: str) -> str:
    """يحوّل اسم الهجوم (مثل neptune) إلى فئته (DoS). أي اسم غير معروف → normal أو خطأ."""
    if attack == NORMAL_LABEL:
        return NORMAL_LABEL
    try:
        return ATTACK_CATEGORY[attack]
    except KeyError as exc:
        raise ValueError(f"Unknown attack name: {attack!r}") from exc


# ---------------------------------------------------------------------------
# وصف عربي لكل ميزة — يُستخدم في شرح التنبيهات بلوحة التحكم والتوثيق
# ---------------------------------------------------------------------------
FEATURE_DESCRIPTIONS_AR: dict[str, str] = {
    "duration": "مدة الاتصال بالثواني",
    "protocol_type": "بروتوكول النقل (tcp / udp / icmp)",
    "service": "الخدمة على الجهاز الهدف (http, ftp, ...)",
    "flag": "حالة الاتصال في TCP (SF = طبيعي مكتمل، S0 = SYN بلا رد، REJ = مرفوض)",
    "src_bytes": "عدد البايتات من المصدر إلى الهدف",
    "dst_bytes": "عدد البايتات من الهدف إلى المصدر",
    "land": "1 إذا كان عنوان/منفذ المصدر = الهدف (هجوم land)",
    "wrong_fragment": "عدد الأجزاء (fragments) الخاطئة",
    "urgent": "عدد الحزم المعلَّمة بـ URG",
    "hot": "عدد المؤشرات 'الساخنة' (دخول مجلدات نظام، تشغيل برامج...)",
    "num_failed_logins": "عدد محاولات تسجيل الدخول الفاشلة",
    "logged_in": "1 إذا نجح تسجيل الدخول",
    "num_compromised": "عدد حالات 'الاختراق' المكتشفة",
    "root_shell": "1 إذا حصل المستخدم على shell بصلاحية root",
    "su_attempted": "1 إذا جُرّب أمر su root",
    "num_root": "عدد العمليات المنفّذة بصلاحية root",
    "num_file_creations": "عدد عمليات إنشاء الملفات",
    "num_shells": "عدد نوافذ shell المفتوحة",
    "num_access_files": "عدد عمليات الوصول لملفات التحكّم",
    "num_outbound_cmds": "عدد الأوامر الصادرة في جلسة ftp",
    "is_host_login": "1 إذا كان الدخول بحساب host",
    "is_guest_login": "1 إذا كان الدخول بحساب ضيف (guest)",
    "count": "عدد الاتصالات لنفس الهدف خلال آخر ثانيتين",
    "srv_count": "عدد الاتصالات لنفس الخدمة خلال آخر ثانيتين",
    "serror_rate": "نسبة اتصالات SYN الفاشلة لنفس الهدف (آخر ثانيتين)",
    "srv_serror_rate": "نسبة اتصالات SYN الفاشلة لنفس الخدمة (آخر ثانيتين)",
    "rerror_rate": "نسبة الاتصالات المرفوضة REJ لنفس الهدف (آخر ثانيتين)",
    "srv_rerror_rate": "نسبة الاتصالات المرفوضة REJ لنفس الخدمة (آخر ثانيتين)",
    "same_srv_rate": "نسبة الاتصالات لنفس الخدمة من بين اتصالات الهدف",
    "diff_srv_rate": "نسبة الاتصالات لخدمات مختلفة من بين اتصالات الهدف",
    "srv_diff_host_rate": "نسبة الاتصالات لأجهزة مختلفة من بين اتصالات الخدمة",
    "dst_host_count": "عدد الاتصالات لنفس الهدف (نافذة آخر الاتصالات)",
    "dst_host_srv_count": "عدد الاتصالات لنفس الهدف والخدمة (نافذة آخر الاتصالات)",
    "dst_host_same_srv_rate": "نسبة نفس الخدمة على الهدف (نافذة الجهاز)",
    "dst_host_diff_srv_rate": "نسبة خدمات مختلفة على الهدف (نافذة الجهاز)",
    "dst_host_same_src_port_rate": "نسبة نفس منفذ المصدر على الهدف (نافذة الجهاز)",
    "dst_host_srv_diff_host_rate": "نسبة أجهزة مختلفة لنفس الخدمة (نافذة الجهاز)",
    "dst_host_serror_rate": "نسبة SYN الفاشلة على الهدف (نافذة الجهاز)",
    "dst_host_srv_serror_rate": "نسبة SYN الفاشلة على الهدف والخدمة (نافذة الجهاز)",
    "dst_host_rerror_rate": "نسبة REJ على الهدف (نافذة الجهاز)",
    "dst_host_srv_rerror_rate": "نسبة REJ على الهدف والخدمة (نافذة الجهاز)",
}

CATEGORY_DESCRIPTIONS_AR: dict[str, str] = {
    "normal": "حركة طبيعية",
    "DoS": "حجب الخدمة — إغراق الهدف بالطلبات",
    "Probe": "استطلاع / مسح للشبكة والمنافذ",
    "R2L": "محاولة دخول غير مصرّح من جهاز بعيد",
    "U2R": "محاولة رفع صلاحيات إلى root",
    "Unknown-Anomaly": "سلوك شاذّ غير معروف (هجوم محتمل جديد / Zero-day)",
}
