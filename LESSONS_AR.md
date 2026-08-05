# شرح الاختبارات بالعربية

## الفكرة
الإضافة لا تهجم الموقع. تقرأ فقط ما يظهر للمتصفح: HTML/JS، التخزين، الروابط، إشارات Firebase.

## اختبارات PDF
| نتيجة | المعنى |
|---|---|
| رابط `https://...pdf` | ملف قد يكون عامًا — اختبر Incognito |
| `firebasestorage.googleapis.com` | تخزين سحابي — يعتمد على token/rules |
| `blob:` | ملف مؤقت في المتصفح |
| لا رابط + زر طباعة/`window.print` | تجهيز ثم Print to PDF |

## اختبارات الحساب / VIP
| إشارة | المعنى |
|---|---|
| `was_vip_USER=false` | مسجّل غالبًا وغير مشترك |
| `was_vip_USER=true` | الواجهة تظنك VIP — يجب تحقق السيرفر |
| مفاتيح auth/token | جلسة على الجهاز |
| JWT في storage | توكن قابل للسرقة عبر XSS |

## Firebase projectId (مثل academie-a2586)
- يظهر أحيانًا في مفاتيح `firestore_zombie_...`  
- **ليس كلمة سر**  
- لا يفتح الملفات لوحده  
- القراءة فقط إن سمحت Security Rules + تسجيل الدخول  

## هل يوجد خطأ؟
- **High**: HTTPS غائب، أسرار قوية، mixed content  
- **Medium**: VIP في localStorage، PDF عام، API مكشوف، JWT  
- **Low/Info**: ملاحظات عادية (CSP meta، كاش SW، مكتبات)  

## تذكير
القفل الحقيقي للمحتوى المدفوع = رفض السيرفر/Firestore، ليس إخفاء الزر فقط.
