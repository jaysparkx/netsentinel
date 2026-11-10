<div dir="rtl">

# 🛡️ NetSentinel — نظام هجين لكشف التسلّل في الشبكات باستخدام تعلّم الآلة

**Hybrid ML-based Network Intrusion & Anomaly Detection System**

مشروع بحثي يجمع **مصنِّفاً مُشرَفاً** يتعرّف على الهجمات المعروفة ويسمّيها، مع **كاشف شذوذ غير مُشرَف** يتعلّم شكل الحركة الطبيعية فقط ليلتقط الهجمات الجديدة (Zero-day) التي لم يرها المصنِّف من قبل.

## ⭐ النتيجة الرئيسية

على مجموعة الاختبار الرسمية **KDDTest+** (22,544 اتصالاً لم يرها النظام أثناء التدريب):

| | المصنِّف وحده | **النظام الهجين** |
|---|---|---|
| نسبة كشف الهجمات | 57.6% | **77.1%** (+19.5 نقطة) |
| الإنذارات الكاذبة | 2.61% | 3.12% (+0.5 نقطة فقط) |
| **كشف الهجمات الجديدة** (17 نوعاً غير موجود في التدريب) | 14.5% | **49.6%** (×3.4) |
| الدقة (Accuracy) | 74.7% | **85.6%** |

ونموذج "الكشف الحي" (من ترويسات الحزم فقط): كشف **78.1%**، والهجمات الجديدة **34.5% ← 71.6%**.

### ✅ وعلى حركة حقيقية حديثة: CIC-IDS2017 (2.2 مليون تدفّق حقيقي، 2017)

درّبنا على الاثنين–الأربعاء واختبرنا على الخميس–الجمعة، أي أن **كل هجمات الاختبار لم يرها النظام قط**:

| | المصنِّف وحده | **الهجين** |
|---|---|---|
| كشف الهجمات الجديدة (إجمالي) | 62.5% | **69.6%** |
| مسح المنافذ (nmap) | 14.7% | **87.0%** |
| الاختراق الداخلي | 0% | **55.6%** |

### ✅ وعلى حزم حقيقية التقطناها من جهازنا (nmap + HTTP flood حقيقيان)

| | النموذج الأساسي | بعد `baseline` على طبيعي الجهاز |
|---|---|---|
| تصفّح طبيعي نظيف | 0 إنذار كاذب | 0 إنذار كاذب |
| nmap port scan | **100%** | **100%** |
| HTTP flood (3000 طلب) | 0% | **89.3%** |

وبالتقسيم العشوائي التقليدي لـ CIC-IDS2017 يصل نفس النظام إلى **99.7%**، وهذا يُثبت أن أرقام "99%" الشائعة في الأبحاث تأتي من طريقة التقييم لا من قوة النموذج. التفاصيل في [10](docs/10_real_traffic_cicids2017.md).

## ✨ المميزات

- 🧠 **نظام هجين بطبقتين** مع قاعدة دمج قرار قابلة للتفسير
- ⚖️ **مقارنة علمية**: 4 مصنِّفات (RF, Gradient Boosting, Logistic Regression, MLP) + كاشفا شذوذ (Isolation Forest, Autoencoder) واختيار الأفضل آلياً
- 🔍 **شرح كل تنبيه** بالعربية: أي ميزة كانت غير طبيعية وبكم (z-score)
- 📡 **يعمل على حركة حقيقية**: يحوّل ملفات pcap أو الالتقاط الحي إلى ميزات NSL-KDD
- 🗂️ **تجميع الحوادث**: 3,308 تنبيهاً من مهاجم واحد ← حادثة واحدة
- 🎯 **ضبط على شبكتك**: أمر `baseline` يعيد تعلّم "الطبيعي" من حركتك
- 🖥️ **موقع خاص بنا** يعمل بدون إنترنت: شريط حزم حيّ، النتائج، تحليل pcap، مختبر، و**عرض حيّ مهاجم ضد مدافع** مع طرفية داخل الموقع
- 📝 واجهة أوامر + تقرير يُولَّد آلياً
- ✅ **36 اختباراً آلياً** ونتائج قابلة للتكرار حرفياً
- 🌍 **مُختبَر على مجموعتي بيانات**: NSL-KDD (معيار أكاديمي) و CIC-IDS2017 (حركة حقيقية حديثة)

## 🚀 البدء السريع

> **للفريق:** كل خطوات التثبيت والتشغيل والاستخدام بالعربية في ملف **[`run.txt`](run.txt)**.
> **أول ملف تقرأه:** [`docs/00_start_here.md`](docs/00_start_here.md) — المشروع كله في 10 دقائق، بلغة بسيطة.

<div dir="ltr">

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e ".[live,web,dev]"

sudo .venv/bin/netsentinel web            # the website → http://127.0.0.1:8000 (sudo = live capture)
.venv/bin/pytest -q                       # 36 tests

# optional — rebuild everything from the raw data
.venv/bin/netsentinel download --dataset all          # NSL-KDD (24 MB) + CIC-IDS2017 (235 MB, SHA-256 verified)
.venv/bin/netsentinel train                           # NSL-KDD, ~5 min → reports/RESULTS.md
.venv/bin/netsentinel train --dataset cicids2017      # real 2017 traffic, ~20 min → reports/RESULTS_CICIDS2017.md
sudo bash tools/capture_real_traffic.sh               # capture REAL packets on this machine (nmap + HTTP flood → 127.0.0.1)
```

</div>

## 📚 التوثيق (اقرأه بهذا الترتيب)

| # | الملف | المحتوى |
|---|---|---|
| 00 | [**ابدأ من هنا**](docs/00_start_here.md) | المشروع كله ببساطة: الفكرة بمثال الحارسين، أين الذكاء الاصطناعي، القاموس، توزيع الأدوار |
| 01 | [الفكرة والمشكلة](docs/01_idea_and_problem.md) | المشكلة، أنواع IDS، فكرة الهجين، الفرضيات البحثية |
| 02 | [البيانات](docs/02_dataset.md) | NSL-KDD، الميزات الـ 41، فئات الهجمات، الهجمات الجديدة |
| 03 | [المعمارية](docs/03_architecture.md) | مخطط النظام، هيكل المجلدات، مبادئ التصميم |
| 04 | [النماذج والخوارزميات](docs/04_models_and_algorithms.md) | شرح كل خوارزمية مع الرياضيات |
| 05 | [التقييم والنتائج](docs/05_evaluation_and_results.md) | كل الأرقام، الحكم على الفرضيات، المناقشة، القيود |
| 06 | [الكشف الحي](docs/06_live_detection.md) | من الحزمة إلى القرار، حالات TCP، الأخلاقيات |
| 07 | [شرح الكود](docs/07_code_walkthrough.md) | كل ملف وكل دالة |
| 08 | [دليل التشغيل](docs/08_run_guide.md) | التثبيت، الأوامر، سيناريو العرض أمام اللجنة |
| 09 | [أسئلة المناقشة](docs/09_defense_qa.md) | أسئلة متوقّعة مع الإجابات |
| 10 | [حركة حقيقية: CIC-IDS2017](docs/10_real_traffic_cicids2017.md) | التجربة على بيانات حقيقية حديثة + التقاط حزم حقيقية من جهازك |

## 🗂️ هيكل المشروع

<div dir="ltr">

```
netsentinel/
├── configs/default.yaml        # all settings
├── src/netsentinel/
│   ├── data/                   # NSL-KDD + CIC-IDS2017 loaders, DatasetSpec
│   ├── features/               # preprocessing pipeline
│   ├── models/                 # supervised, anomaly, hybrid
│   ├── evaluation/             # metrics + plots
│   ├── explain/                # permutation importance
│   ├── live/                   # packets → connections → features
│   ├── pipeline/               # training + report
│   ├── alerts.py               # incident grouping
│   ├── web/                    # the website: FastAPI server, attack range, static page
│   └── cli.py
├── run.txt                     # how to install, run and use it (Arabic, step by step)
├── app/dashboard.py            # older Streamlit dashboard (kept as backup)
├── tools/make_demo_pcap.py
├── tools/capture_real_traffic.sh
├── tests/                      # 36 pytest tests
├── docs/                       # Arabic documentation (00–10)
└── reports/                    # generated results + figures
```

</div>

## ⚠️ ملاحظات مهمة

- **الأخلاقيات:** التقط الحركة فقط على شبكة تملكها أو بإذن كتابي.
- **الأمان:** ملفات النماذج (`.joblib`) تُحمَّل بـ pickle — لا تحمّل نموذجاً من مصدر غير موثوق.
- **القيود:** NSL-KDD من 1998؛ هجمات SNMP (جزء من R2L) غير قابلة للتمييز بهذه الميزات. التفاصيل في [05](docs/05_evaluation_and_results.md#9-القيود-والعمل-المستقبلي).

## 📖 المراجع

1. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). *A Detailed Analysis of the KDD CUP 99 Data Set*. IEEE CISDA.
2. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). *Isolation Forest*. IEEE ICDM.
3. Breiman, L. (2001). *Random Forests*. Machine Learning, 45(1).
4. Hinton, G. E., & Salakhutdinov, R. R. (2006). *Reducing the Dimensionality of Data with Neural Networks*. Science.
5. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
6. Engelen, G., Rimmer, V., & Joosen, W. (2021). *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*. IEEE SPW.
7. Sommer, R., & Paxson, V. (2010). *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection*. IEEE S&P.

</div>
