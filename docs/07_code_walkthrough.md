<div dir="rtl">

# 07 — شرح الكود: ملفاً ملفاً ودالةً دالة

> **طريقة القراءة المقترحة للفريق:** افتح هذا الملف بجانب الكود. كل دالة هنا مشروحة بـ: **ماذا تفعل ← لماذا ← ملاحظة مهمة**. وداخل الكود نفسه ستجد تعليقات عربية في كل ملف.

## كيف تقرأ الكود إذا لم تكن مبرمجاً؟

1. **لا تقرأ كل شيء.** ابدأ بالملف الذي يخصّ الجزء الذي ستشرحه.
2. **اقرأ التعليقات العربية أولاً** — كل ملف يبدأ بشرح فكرته، وكل دالة مهمة تحتها شرح.
3. **الجملة `def اسم(...)`** = تعريف دالة (وصفة تأخذ مدخلات وتُرجع نتيجة).
4. **`class اسم`** = صنف (قالب يجمع بيانات ودوال معاً، مثل `HybridIDS`).
5. **السطر الذي يبدأ بـ `#`** = تعليق للبشر، لا يُنفَّذ.

**الملفات الثلاثة الأهم للفهم:** `models/hybrid.py` (القرار)، `models/anomaly.py` (الـ Autoencoder)، `web/attack_range.py` (العرض الحي).

## خريطة الاعتماديات (من يستدعي من)

```
cli.py  ──►  web/server.py  ──►  web/attack_range.py
   │              └─► (نفس الوحدات أدناه)
   └─► pipeline/train.py ──► data/loader.py ──► data/schema.py
            │                features/preprocessing.py
            │                models/supervised.py, models/anomaly.py
            │                models/hybrid.py
            │                evaluation/metrics.py, evaluation/plots.py
            │                explain/importance.py
            └─► pipeline/report.py
   └─► live/capture.py ──► live/flow.py
   └─► alerts.py
```

---

## 1. `config.py` — الإعدادات

| العنصر | ماذا يفعل | لماذا |
|---|---|---|
| `PROJECT_ROOT` | مسار جذر المشروع محسوباً من موقع الملف | يعمل الكود من أي مجلد تشغّله منه |
| `PathsConfig`, `DataConfig`, ... | `dataclass` لكل قسم في YAML | الأنواع واضحة، والخطأ الإملائي يظهر فوراً |
| `_resolve(path_str)` | يحوّل المسار النسبي لمطلق | `data/raw` في YAML ← المسار الكامل |
| `load_config(path)` | يقرأ YAML ويبني `Config` | أي مفتاح ناقص يأخذ القيمة الافتراضية |

---

## 2. `data/schema.py` — "قاموس" البيانات

لا يحوي منطقاً تقريباً، بل **ثوابت** يعتمد عليها كل المشروع:

| الثابت | المحتوى |
|---|---|
| `BASIC_FEATURES` ... `HOST_TRAFFIC_FEATURES` | أسماء الميزات في مجموعاتها الأربع |
| `RAW_COLUMNS` | الأعمدة الـ 43 بترتيب الملف الخام |
| `CATEGORICAL_FEATURES` | النصية الثلاث: protocol_type, service, flag |
| `CONSTANT_FEATURES` | `num_outbound_cmds` (صفر دائماً ← نحذفها) |
| `SKEWED_FEATURES` | الميزات التي نطبّق عليها log1p |
| `FEATURE_PROFILES` | `full` (40) و`live` (28) |
| `ATTACK_CATEGORY` | 39 هجوماً ← فئاتها الأربع |
| `FEATURE_DESCRIPTIONS_AR` | وصف عربي لكل ميزة (يظهر في شرح التنبيهات) |

**`attack_to_category(attack)`** — `"neptune"` ← `"DoS"`. اسم غير معروف ← خطأ صريح (`ValueError`) بدل أن يمرّ بصمت. *(مبدأ: Fail fast.)*

---

## 2b. `data/spec.py` — مواصفات مجموعة البيانات

`DatasetSpec` كائن يصف أي مجموعة بيانات: `features`, `categorical`, `skewed`, `class_names`, `descriptions`. كل أجزاء النظام (المعالجة، الهجين، التفسير، التقييم) تقرأ منه، فيعمل **نفس الكود** على NSL-KDD و CIC-IDS2017. `nsl_kdd_spec(profile)` يبني مواصفات NSL-KDD.

## 2c. `data/cicids.py` — CIC-IDS2017

| العنصر | ماذا يفعل |
|---|---|
| `DAY_FILES` | ملفات CSV لكل يوم (الأساس للتقسيم الزمني) |
| `DROPPED_COLUMNS` | الأعمدة المحذوفة مع **سبب كل حذف** (shortcut / duplicate / constant) |
| `ATTACK_CATEGORY`, `CLASS_NAMES` | 15 تسمية ← 9 فئات |
| `download_cicids()` | تنزيل + **تحقّق SHA-256** + فكّ الضغط |
| `_clean_label()` | يصلح الحرف المكسور `�` في أسماء هجمات الويب |
| `load_cicids(raw_dir, days)` | تحميل + حذف Inf/NaN + حذف المكرّر + float32 + تخزين مؤقت (cache) |
| `cicids_spec(profile)` | مواصفات الـ 68 ميزة (كلها تمرّ بـ signed log) |

## 3. `data/loader.py` — التحميل

| الدالة | ماذا تفعل | ملاحظة |
|---|---|---|
| `download_nsl_kdd(raw_dir, force)` | تنزّل الملفات الثلاثة | تتخطّى الموجود (إلا مع `force`) |
| `load_split(raw_dir, split)` | تقرأ ملفاً وتضيف `category` و`is_attack` | `is_attack` للتصنيف الثنائي، `category` للخماسي |
| `mark_novel_attacks(test_df, train_df)` | تضيف `is_novel=1` لكل هجوم في الاختبار لم يظهر في التدريب | **أساس تجربة Zero-day** |

---

## 4. `features/preprocessing.py` — المعالجة المسبقة

| الدالة | ماذا تفعل |
|---|---|
| `split_feature_types(features)` | تقسّم قائمة الميزات إلى (نصية، ذيل طويل، عادية) |
| `build_preprocessor(profile)` | تبني `ColumnTransformer` بثلاثة فروع: OneHot / log1p+Scale / Scale |
| `select_features(df, profile)` | تُرجع أعمدة الملف المطلوب فقط، وتعطي خطأً واضحاً إن نقص عمود |

**`signed_log1p(x)`** = `sign(x)·log(1+|x|)` — مثل log1p لكنه يقبل القيم السالبة (بعض ميزات CIC سالبة).

**سطر مهم:** `OneHotEncoder(handle_unknown="ignore")` ← خدمة جديدة في الاختبار لا توقف البرنامج.

---

## 5. `models/supervised.py` — المصنِّفات

- `_random_forest`, `_hist_gradient_boosting`, `_logistic_regression`, `_mlp` — كل دالة تُنشئ نموذجاً **غير مدرَّب** بإعدادات مختارة ومشروحة.
- `SUPERVISED_MODELS` — قاموس: الاسم ← دالة الإنشاء.
- `build_classifier(name, seed)` — **نمط المصنع (Factory)**: نختار النموذج بالاسم من YAML. لإضافة نموذج جديد (مثلاً XGBoost): دالة واحدة + سطر في القاموس.

---

## 6. `models/anomaly.py` — كواشف الشذوذ

### `AnomalyDetector` (صنف مجرّد — Abstract Base Class)
يفرض على كل كاشف أن يوفّر `fit` و`score`، ويوفّر هو منطق العتبة المشترك:

| الدالة | ماذا تفعل |
|---|---|
| `fit(X_normal)` | *(مجرّدة)* تدريب على الطبيعي فقط |
| `score(X)` | *(مجرّدة)* درجة شذوذ — أعلى = أغرب |
| `calibrate(X_normal, percentile)` | العتبة = النسبة المئوية من درجات طبيعي التحقق |
| `predict(X)` | 0/1 حسب العتبة، وترفض العمل إن لم تُعايَر |

### `IsolationForestDetector`
`score` = **سالب** `score_samples` (لأن sklearn يعطي قيمة أعلى للطبيعي، ونحن نريد العكس).

### `AutoencoderDetector`
- `fit`: `model.fit(X, X)` — الهدف هو الإدخال نفسه.
- `score`: متوسط مربّع الفرق بين الإدخال وإعادة البناء (MSE) لكل سجل.
- نكتم `ConvergenceWarning` عمداً لأن عدد الدورات ثابت (60) بقرار تجريبي موثّق.

`build_detector(name)` — مصنع مثل `build_classifier`.

---

## 7. `models/hybrid.py` — قلب النظام

### `NormalBaseline`
"بصمة الطبيعي": `mean`, `std` لكل ميزة رقمية (بعد log1p) + `category_freq` (تكرار كل قيمة نصية).
`from_frame(X_normal)` تبنيها من سجلات طبيعية. `std` الصفري يُستبدل بـ `1e-6` لتجنّب القسمة على صفر.

### `HybridIDS`
| الدالة | ماذا تفعل |
|---|---|
| `__init__` | يجمع: الملف، المعالجة، المصنِّف، الكاشف، البصمة، البيانات الوصفية |
| `transform(df)` | اختيار الأعمدة + المعالجة ← مصفوفة أرقام |
| `predict(df)` | **قاعدة الدمج**: يحسب رأي المصنِّف + درجة الشذوذ ← `final_label`, `is_alert`, `severity` |
| `explain(row, top_k)` | z-score لكل ميزة مقابل البصمة ← أكبرها (≥ 2) + القيم النصية النادرة (< 1%) |
| `refit_baseline(df_normal)` | يعيد تدريب الكاشف والبصمة على حركة شبكتك (80% تدريب / 20% معايرة) |
| `save(path)` / `load(path)` | حفظ وتحميل بـ joblib |

**قاعدة الدمج في الكود** (`predict`):
```python
final = np.where(clf_label != "normal", clf_label,
         np.where(is_anomaly, "Unknown-Anomaly", "normal"))
```

**⚠️ ملاحظة أمنية:** `joblib.load` يعتمد على `pickle` الذي **قد ينفّذ كوداً** عند التحميل. لا تحمّل نموذجاً من مصدر غير موثوق — نقطة جيدة لذكرها في مشروع أمن سيبراني.

---

## 8. `evaluation/metrics.py` — المقاييس

| الدالة | المُخرَج |
|---|---|
| `binary_metrics(y_true, y_pred, y_score)` | accuracy, precision, **detection_rate**, **false_alarm_rate**, f1, tp/fp/tn/fn, roc_auc |
| `multiclass_metrics(y_true, y_pred)` | accuracy, f1_macro, f1_weighted, تقرير لكل فئة |
| `detection_rate_by_group(is_alert, groups)` | نسبة الكشف لكل فئة (أو أي تجميع) |
| `evaluate_hybrid(test_df, predictions)` | **التقييم الشامل**: الأوضاع الثلاثة + لكل فئة + الهجمات الجديدة |
| `attack_score(predictions)` | درجة "هجوم" من المصنِّف لرسم ROC |

## 9. `evaluation/plots.py` — الرسوم
دالة لكل رسم: `plot_confusion_matrix`, `plot_roc_curves`, `plot_anomaly_scores`, `plot_model_comparison`, `plot_feature_importance`, `plot_novel_detection`. كلها تحفظ PNG بدقة 150 DPI عبر `_save`. نستخدم `matplotlib.use("Agg")` ليعمل الرسم بدون شاشة.

## 10. `explain/importance.py`
`compute_permutation_importance(model, df, n_samples)` — يلفّ المعالجة + المصنِّف في `Pipeline` واحد حتى يخلط **الأعمدة الأصلية** (service كاملة، لا أعمدة One-Hot مفكّكة)، 5 تكرارات لكل ميزة.

---

## 11. `live/flow.py` — الحزم ← الميزات (بدون scapy)

| العنصر | ماذا يفعل |
|---|---|
| `TCP_SERVICES`, `UDP_SERVICES`, `ICMP_SERVICES` | منفذ ← اسم الخدمة بتسميات NSL-KDD |
| `port_to_service(protocol, port)` | المجهول: `< 1024` ← other، وغير ذلك ← private |
| `PacketInfo` | حزمة مبسّطة (`frozen` = لا تتغيّر بعد الإنشاء) |
| `Connection` | حالة اتصال: البايتات بالاتجاهين + أحداث TCP |
| `Connection.flag` | **آلة الحالة** (State machine) التي تحوّل الأحداث إلى SF/S0/REJ/... |
| `assemble_connections(packets, idle_timeout)` | يجمع الحزم باتجاهين في اتصالات |
| `_record_tcp_event(conn, flags, from_originator)` | يسجّل SYN/SYN-ACK/FIN/RST ومن أرسلها |
| `connections_to_features(connections)` | لكل اتصال: الأساسية + نافذة الثانيتين + نافذة الـ 255 اتصالاً |
| `_time_features`, `_host_features` | حساب النسب داخل كل نافذة |
| `_rate(part, total)` | قسمة آمنة (0 إذا المقام صفر) مقرّبة لخانتين كما في NSL-KDD |

**لماذا هو منفصل عن scapy؟** لنختبر منطق TCP بحزم نصنعها يدوياً (انظر `tests/test_flow.py`) دون شبكة أو صلاحيات.

## 12. `live/capture.py` — Scapy

| الدالة | ماذا تفعل |
|---|---|
| `_require_scapy()` | رسالة خطأ واضحة إن لم تكن scapy مثبّتة + تفعيل فكّ الترويسات فقط |
| `_decode_headers_only(scapy)` | يطلب من Scapy فكّ IP/TCP/UDP/ICMP فقط وترك الحمولة خاماً (منع انهيار "recursion depth" أثناء الـ flood). يُفعَّل مرة واحدة فقط |
| `to_packet_info(pkt)` | حزمة scapy ← `PacketInfo` (أو None إن لم تكن IPv4) |
| `_ip_payload_length(ip)` | الطول الحقيقي من ترويسة IP — لأن tcpdump قد يقصّ الحزمة (snaplen) |
| `packets_to_features(packets)` | قائمة حزم ← جدول ميزات |
| `read_pcap_features(path)` | ملف pcap ← جدول ميزات |
| `live_capture(on_batch, interface, ..., should_stop)` | حلقة: التقاط دفعة ← ميزات بسياق 120 ث ← `on_batch` للجديد فقط. دفعة فاشلة لا توقف الحلقة. `should_stop` يوقفها عند إغلاق الصفحة |

## 13. `alerts.py`
`group_incidents(features, predictions)` — يجمع التنبيهات حسب (المصدر، الهدف، النوع) ← حادثة واحدة بعدد الاتصالات وعدد المنافذ المختلفة وأخطر سجل. **يعالج "إرهاق التنبيهات"**: 3,308 تنبيه ← حادثة واحدة.

## 14. `pipeline/train.py` — خطّ التدريب

| الدالة | ماذا تفعل |
|---|---|
| `model_path(cfg, run)` | `artifacts/<run>/hybrid_ids.joblib` |
| `_select_classifier(...)` | يدرّب كل المرشّحين ← جدول مقارنة ← الأفضل بـ Macro-F1 |
| `_select_detector(...)` | يدرّب الكواشف على الطبيعي ← يعاير ← الأفضل بـ ROC-AUC |
| `train_hybrid(cfg, spec, train_df, run)` | تقسيم طبقي 80/20 ← معالجة ← اختيار ← تجميع ← حفظ (لأي مجموعة بيانات) |
| `evaluate_model(cfg, model, run, selection, test_sets)` | تقييم على ملفات الاختبار + كل الرسوم + أهمية الميزات + `metrics.json` |
| `threshold_sensitivity(model, test_df, pred)` | الكشف/الإنذار الكاذب عند 5 عتبات (محسوبة من التحقق) |
| `run_training(cfg, profiles)` | تجربة NSL-KDD: الملفّان ← RESULTS.md |

## 14b. `pipeline/cicids_experiments.py`
| الدالة | ماذا تفعل |
|---|---|
| `balanced_sample(df, normal_n, attack_cap)` | عيّنة تدريب متوازنة (النادر كاملاً، الكبير مقصوص) |
| `run_random_split` | تجربة ①: الأيام مختلطة، 30% اختبار |
| `run_temporal_split` | تجربة ②: تدريب الاثنين–الأربعاء، اختبار الخميس–الجمعة |
| `run_cicids` | التجربتان ← RESULTS_CICIDS2017.md |

## 15. `pipeline/report.py`
`write_report(cfg, results, filename, title)` ← `reports/RESULTS.md` (أو `RESULTS_CICIDS2017.md`) بالعربية من الأرقام مباشرةً (لا نسخ يدوي).

## 16. `cli.py` — الأوامر
كل أمر دالة `cmd_*`، و`build_parser()` يربط الأسماء بالدوال. `_print_alerts` يطبع الملخّص ثم الحوادث مع شرحها. `_load_model` يقبل `--model` لنموذج مخصّص.

## 17. `web/` — الموقع ⭐ (ما تعرضونه أمام اللجنة)

### كيف يعمل الموقع (بمثال المطعم)
- **المتصفّح** = الزبون: يطلب ("حلّل هذا الملف").
- **`server.py`** = النادل: يستلم الطلب، يأخذه للمطبخ، ويرجع بالنتيجة.
- **النماذج** = الطبّاخ: تحكم على الاتصالات.
- الطلبات والردود بصيغة **JSON** (نص منظّم)، والبثّ الحي بتقنية **SSE** (الخادم يرسل أسطراً متتالية دون أن يطلبها المتصفّح كل مرة).

### `web/server.py` — الخادم (FastAPI)

| المسار (API) | ماذا يفعل |
|---|---|
| `GET /` | يرسل الصفحة `index.html` |
| `GET /api/status` | النماذج والملفات المتاحة، وهل الخادم يعمل بـ root |
| `GET /api/results/{run}` | نتائج تجربة من `reports/<run>/metrics.json` |
| `POST /api/analyze` | يحلّل pcap (جاهز أو مرفوع) ← ملخّص + حوادث مشروحة + نقاط الشريط |
| `GET /api/replay` | **بثّ** ملف pcap اتصالاً اتصالاً بتوقيته الأصلي (قسم Tape) |
| `GET /api/live` | **بثّ** الالتقاط الحي من كرت الشبكة (يحتاج root) |
| `GET /api/range` | حالة ميدان الهجوم (ما يعمل الآن) |
| `POST /api/range/command` | أمر من طرفية الموقع (قائمة ثابتة فقط) |
| `POST /api/range/auto` | تشغيل/إيقاف وضع الهجوم التلقائي |
| `POST /api/range/background` | تشغيل/إيقاف التصفّح الطبيعي |
| `GET /api/range/console` | **بثّ** أسطر الطرفية (مخرجات nmap الحقيقية) |
| `GET /api/lab/presets` و `POST /api/lab` | المختبر: نقاط البداية، وقرار النظام على اتصال واحد |

| دالة مساعدة | ماذا تفعل |
|---|---|
| `_features_for(path)` | تحويل pcap ← ميزات **مرة واحدة فقط**: قفل (لا قراءة مزدوجة) + تخزين في الذاكرة وعلى القرص `data/cache/` |
| `_pcap_model(custom)` | النموذج الحي، أو نسخته المضبوطة على طبيعي الجهاز |
| `_event(...)` | يحوّل اتصالاً واحداً إلى حدث للبثّ؛ يحسب الشرح فقط لأول اتصال من كل حادثة (توفيراً للوقت) |
| `_local_only(request)` | يرفض أوامر الهجوم إن لم تأتِ من نفس الجهاز |
| `_sse(event, data)` | صيغة سطر البثّ: `event: …` ثم `data: {JSON}` |

### `web/attack_range.py` — ميدان الهجوم

| العنصر | ماذا يفعل |
|---|---|
| `TARGET = "127.0.0.1"` | الهدف **ثابت في الكود** — لا يُقبل غيره |
| `_VictimServer` | خادم ويب "ضحية" على المنفذ 8088؛ يتجاهل أخطاء BrokenPipe المتوقّعة تحت الإغراق |
| `ATTACKS` | الهجمات الثلاث: الاسم، الأداة الحقيقية، الوصف العربي، المتوقّع |
| `ensure_victim()` | يشغّل الضحية مرة واحدة |
| `set_background(on)` | تصفّح "بشري": طلب كل 0.3–1.5 ثانية |
| `launch(attack_id)` | يشغّل هجوماً في خيط خلفي (thread) |
| `_nmap(args)` | يشغّل nmap الحقيقي ويبثّ مخرجاته **سطراً سطراً** إلى طرفية الموقع |
| `_http_flood()` | 3000 طلب عبر 100 خيط متوازٍ، مع تقدّم كل 500 طلب |
| `set_auto(on)` / `_auto_loop()` | وضع الهجوم: مسح ← توقّف 10 ث ← إغراق ← ... حتى الإيقاف |
| `run_command(text)` | **قائمة بيضاء** (whitelist) من 8 أوامر. أي نص آخر ← "command not allowed". السبب: الخادم root، وتنفيذ نصّ حرّ = ثغرة RCE |
| `say(text, stream)` | يضيف سطراً لطرفية الموقع (cmd / out / info / err) |

### `web/static/` — الصفحة نفسها

| الملف | ماذا فيه |
|---|---|
| `index.html` | هيكل الأقسام الستة |
| `styles.css` | التصميم: أسود، خطوط شبكية، الألوان تعني قرارات (رمادي طبيعي، برتقالي مسح، أحمر هجوم، سماوي شذوذ) |
| `app.js` | المنطق: `Tape` (رسم الشريط على Canvas)، الرسوم البيانية (SVG يدوي بدون مكتبات)، الاتصال بالـ API والبثّ |
| `fonts/` | Departure Mono و IBM Plex Sans Arabic — مضمّنة ليعمل الموقع بدون إنترنت (رخصة مفتوحة OFL) |

**`Tape` في `app.js`:** كل اتصال خط عمودي؛ المحور الأفقي = الزمن، الارتفاع = log(درجة الشذوذ)، الخط المتقطّع = العتبة. في الوضع الحي يتحرّك الزمن مع الساعة الحقيقية، وكل هجوم يُطلَق يُرسم كعلامة "▶ Port scan".

### `app/dashboard.py` — النسخة القديمة (Streamlit)
لوحة سابقة ما زالت تعمل (`streamlit run app/dashboard.py`)، لكن الموقع الجديد يغني عنها. نحتفظ بها كنسخة احتياطية.

## 18. `tools/make_demo_pcap.py`
يصنع `demo_normal.pcap` و`demo_attack.pcap` بـ Scapy: جلسات HTTP كاملة، DNS، SYN Flood، Port Scan، Ping Sweep. **لا يرسل شيئاً لأي شبكة.**

## 19. `tests/` — 38 اختباراً
| الملف | يختبر |
|---|---|
| `conftest.py` | يصنع بيانات صناعية "منطقية" بأعمدة NSL-KDD |
| `test_data_and_features.py` | الفئات، ملفات الميزات، المعالجة، الخدمات المجهولة، الهجمات الجديدة |
| `test_models.py` | كل مصنِّف، كل كاشف، قاعدة الدمج، التفسير، الحفظ/التحميل، المقاييس بقيم محسوبة يدوياً، تجميع الحوادث، إعادة ضبط خط الأساس |
| `test_flow.py` | الخدمات، SF/S0/REJ، ميزات SYN flood، انتهاء المهلة، الطول الحقيقي مع snaplen، تفعيل فكّ الترويسات أكثر من مرة |
| `test_cicids.py` | إصلاح الأسماء، قائمة الميزات، signed log، المعالجة، العيّنة المتوازنة |

</div>
