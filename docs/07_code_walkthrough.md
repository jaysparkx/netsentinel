<div dir="rtl">

# ‏07 - شرح الكود

‏افتح هذا الملف بجانب الكود. لكل ملف: ما فيه وما تفعله أهم دواله.

‏ترتيب الاستدعاء باختصار:

```
cli.py -> pipeline/train.py -> data/ + features/ + models/ + evaluation/
cli.py -> live/capture.py -> live/flow.py
cli.py -> web/server.py -> web/attack_range.py
```

## config.py

‏`load_config(path)` يقرأ `configs/default.yaml` ويحوّله إلى كائن نصل لقيمه بالنقطة (`cfg.paths.raw_dir`). المسارات النسبية تُحسب من جذر المشروع `PROJECT_ROOT` حتى يعمل الأمر من أي مجلد.

## data/schema.py

‏ثوابت NSL-KDD: أسماء الميزات بمجموعاتها الأربع، `RAW_COLUMNS` بترتيب الملف الخام، الميزات النصية الثلاث، `num_outbound_cmds` (صفر دائماً فنحذفها)، الميزات التي نطبق عليها log1p، و`FEATURE_PROFILES` (full فيه 40 ميزة و live فيه 28).

‏`ATTACK_CATEGORY` يربط كل هجوم من الـ 39 بفئته (DoS, Probe, R2L, U2R). `attack_to_category("neptune")` تعطي `"DoS"`، واسم غير معروف يعطي `ValueError`.

‏`FEATURE_DESCRIPTIONS` و `CATEGORY_DESCRIPTIONS` نصوص إنجليزية قصيرة تظهر في شرح التنبيهات.

## data/spec.py

‏`DatasetSpec` يصف مجموعة البيانات: الميزات، النصية منها، المنحرفة، أسماء الفئات، والأوصاف. المعالجة والنموذج والتقييم كلها تقرأ منه، لذلك نفس الكود يعمل على NSL-KDD و CIC-IDS2017. `nsl_kdd_spec(profile)` يبنيه لـ NSL-KDD.

## data/loader.py

- ‏`download_nsl_kdd(raw_dir, force)` تنزل الملفات وتتخطى الموجود.
- ‏`load_split(raw_dir, split)` تقرأ ملفاً وتضيف عمودي `category` و `is_attack`.
- ‏`mark_novel_attacks(test_df, train_df)` تضع `is_novel=1` لكل هجوم في الاختبار لم يظهر في التدريب. هذا أساس تجربة الهجمات الجديدة.

## data/cicids.py

- ‏`FEATURES` الميزات الـ 68 التي نستخدمها، و `DROPPED_COLUMNS` ما حذفناه (منفذ الهدف لأنه يكشف الجواب، والأعمدة المكررة أو الثابتة).
- ‏`download_cicids` تنزل الملف المضغوط وتتحقق من SHA-256 ثم تفك الضغط.
- ‏`_clean_label` تصلح الحرف المكسور في أسماء هجمات الويب.
- ‏`load_cicids(raw_dir, days)` تقرأ الأيام المطلوبة، تحذف Inf/NaN والمكرر، وتحفظ نسخة `clean_*.pkl` لتسريع المرة القادمة.
- ‏`cicids_spec` يبني الـ DatasetSpec، وكل الميزات تمر بـ signed log.

## features/preprocessing.py

- ‏`signed_log1p(x)` = `sign(x) * log(1 + |x|)`، مثل log1p لكنها تقبل القيم السالبة.
- ‏`build_preprocessor(spec)` يبني `ColumnTransformer`: OneHot للنصية، log ثم Scale للمنحرفة، Scale للباقي. `handle_unknown="ignore"` يعني أن خدمة جديدة في الاختبار لا توقف البرنامج.
- ‏`select_features(df, spec)` ترجع الأعمدة المطلوبة فقط وتعطي خطأ واضحاً إن نقص عمود.

## models/supervised.py

‏`CLASSIFIER_NAMES` أسماء المصنفات الأربعة، و `build_classifier(name, seed)` تنشئ المطلوب منها (Random Forest, HistGradientBoosting, Logistic Regression, MLP).

## models/anomaly.py

- ‏`AnomalyDetector` الصنف الأب. `calibrate` تجعل العتبة النسبة 99 من درجات الطبيعي، و `predict` تعطي 1 إذا تجاوزت الدرجة العتبة.
- ‏`IsolationForestDetector` الدرجة هي سالب `score_samples` (لأن sklearn يعطي الطبيعي قيمة أعلى).
- ‏`AutoencoderDetector` شبكة `MLPRegressor` بطبقات (64, 16, 8, 16, 64) تتعلم `fit(X, X)`. الدرجة هي خطأ إعادة البناء (MSE) لكل سجل.
- ‏`build_detector(name)` تنشئ الكاشف بالاسم.

## models/hybrid.py

‏`NormalBaseline` يحفظ متوسط وانحراف كل ميزة رقمية في الحركة الطبيعية وتكرار كل قيمة نصية. نستعمله في الشرح.

‏`HybridIDS` يجمع المعالجة والمصنف والكاشف والـ baseline:

- ‏`predict(df)` قاعدة الدمج:

```python
final = np.where(clf_label != "normal", clf_label,
         np.where(is_anomaly, "Unknown-Anomaly", "normal"))
```

- ‏`explain(row)` تحسب z-score لكل ميزة مقارنة بالطبيعي وترجع الأكبر، مع القيم النصية النادرة.
- ‏`refit_baseline(df_normal)` تعيد تدريب الكاشف على حركة شبكتنا (80% تدريب و 20% لحساب العتبة).
- ‏`save` و `load` بـ joblib. ملاحظة أمنية: joblib يستخدم pickle، فلا نحمل نموذجاً من مصدر غير موثوق.

## ‏evaluation/metrics.py و plots.py

- ‏`binary_metrics` تعطي accuracy, precision, detection rate, false alarm rate, f1, roc_auc.
- ‏`multiclass_metrics` لكل الفئات، و `detection_rate_by_group` نسبة الكشف لكل فئة.
- ‏`evaluate_hybrid` تقيّم الأوضاع الثلاثة (المصنف فقط، الكاشف فقط، الهجين) والهجمات الجديدة.
- ‏`plots.py` دالة لكل رسم (confusion, ROC, درجات الشذوذ, مقارنة النماذج, أهمية الميزات, الهجمات الجديدة, حساسية العتبة) وكلها تحفظ PNG.

## explain/importance.py

‏`compute_permutation_importance` تخلط كل عمود أصلي وترى كم ينخفض الأداء.

## live/flow.py

‏يحول الحزم إلى اتصالات ثم إلى الـ 28 ميزة، بدون scapy حتى نختبره بحزم نصنعها يدوياً.

- ‏`port_to_service` من رقم المنفذ إلى اسم الخدمة كما في NSL-KDD.
- ‏`PacketInfo` حزمة مبسطة، و `Connection` اتصال بالبايتات في الاتجاهين وأحداث TCP. `Connection.flag` تحسب SF / S0 / REJ ... من الأحداث.
- ‏`assemble_connections` تجمع الحزم في اتصالات، و `add_tcp_event` تسجل SYN و FIN و RST ومن أرسلها.
- ‏`connections_to_features` تحسب الميزات، ومعها `time_features` (آخر ثانيتين) و `host_features` (آخر 255 اتصالاً). `rate` قسمة تعطي صفراً إذا كان المقام صفراً.

## live/capture.py

- ‏`_require_scapy` تستورد scapy وتطلب فك ترويسات IP/TCP/UDP/ICMP فقط (فك الحمولة كان يسبب خطأ recursion أثناء الـ flood).
- ‏`_bigger_bpf_buffer` على الماك فقط: buffer الافتراضي 64KB يمتلئ أثناء nmap فتضيع حزم، فنكبّره.
- ‏`ip_payload_length` الطول من ترويسة IP، لأن tcpdump قد يقص الحزمة.
- ‏`to_packet_info`, `packets_to_features`, `read_pcap_features` من scapy إلى جدول ميزات.
- ‏`live_capture` تلتقط في الخلفية (AsyncSniffer) وتحلل كل `batch_seconds`، وكل اتصال يُرسل مرة واحدة فقط.

## alerts.py

‏`group_incidents` تجمع التنبيهات حسب (المصدر، الهدف، النوع) في حادثة واحدة مع عدد الاتصالات والمنافذ. مثلاً 3,308 تنبيه من nmap تصبح حادثة واحدة.

## pipeline/train.py

- ‏`pick_classifier` تدرب المصنفات الأربعة وتختار الأفضل بـ macro-F1.
- ‏`pick_detector` تدرب الكاشفين على الطبيعي وتختار الأفضل بـ ROC-AUC.
- ‏`train_hybrid` تقسيم 80/20 ثم المعالجة ثم الاختيار ثم الحفظ في `artifacts/<run>/hybrid_ids.joblib`.
- ‏`threshold_sensitivity` الكشف والإنذار الكاذب عند 5 عتبات.
- ‏`evaluate_model` تقيم على ملفات الاختبار وترسم وتكتب `metrics.json`.
- ‏`run_training` تشغل تجربتي full و live وتكتب `reports/RESULTS.md`.

## pipeline/cicids_experiments.py

- ‏`balanced_sample` عينة تدريب: كل الهجمات النادرة، والكبيرة مقصوصة.
- ‏`run_random_split` الأيام مختلطة و 30% اختبار.
- ‏`run_temporal_split` تدريب الاثنين إلى الأربعاء واختبار الخميس والجمعة.

## pipeline/report.py

‏`write_report` تكتب ملف النتائج من الأرقام مباشرة.

## cli.py

‏كل أمر دالة `cmd_*` (download, train, predict, pcap, live, baseline, web)، و `build_parser` تربط الأسماء بالدوال. `print_alerts` تطبع الملخص والحوادث.

## web/server.py

‏خادم FastAPI:

- ‏`GET /` الصفحة.
- ‏`GET /api/status` النماذج والعينات المتاحة وهل الخادم يعمل بـ root.
- ‏`GET /api/results/{run}` نتائج تجربة من `metrics.json`.
- ‏`POST /api/analyze` تحليل pcap (عينة أو ملف مرفوع) وإرجاع الحوادث.
- ‏`GET /api/live` بث الالتقاط الحي (SSE، يحتاج root).
- ‏`GET /api/range` و `POST /api/range/command` و `GET /api/range/console` ميدان الهجوم وطرفيته.
- ‏`POST /api/lab` قرار النظام على اتصال واحد نكتب قيمه بأيدينا.

‏`sample_features` تحول ملف pcap إلى ميزات مرة واحدة وتحفظها في `data/cache/`. `local_only` ترفض أوامر الهجوم إن لم تأت من نفس الجهاز.

## web/attack_range.py

- ‏`TARGET = "127.0.0.1"` الهدف ثابت.
- ‏`VictimServer` خادم ويب ضحية على المنفذ 8088.
- ‏`ATTACKS` الهجمات الثلاث (port scan, service scan, http flood).
- ‏`set_browsing` تصفح طبيعي في الخلفية، `launch` تشغل هجوماً، `_nmap` تشغل nmap الحقيقي وتبث مخرجاته، `_flood` 3000 طلب من 100 خيط.
- ‏`set_auto` و `_auto_loop` تشغيل الهجمات بالتتابع.
- ‏`run_command` قائمة أوامر ثابتة فقط. أي نص آخر يعطي "command not allowed"، لأن الخادم يعمل بـ root.

## web/static/

‏`index.html` الأقسام الأربعة (النتائج، التحليل، المراقبة الحية، المختبر)، `style.css` تنسيق بسيط، `main.js` يجلب البيانات من الـ API ويعرضها.

## tests/

‏38 اختباراً: `conftest.py` يصنع بيانات صغيرة، `test_data_and_features.py` البيانات والمعالجة، `test_models.py` النماذج والدمج والشرح والمقاييس، `test_flow.py` بناء الاتصالات والالتقاط، `test_cicids.py` بيانات CIC-IDS2017.

</div>
