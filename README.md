# Web Public Security Scanner

إضافة متصفح (Chrome/Edge/Brave) للفحص الأمني **القراءة فقط** خطوة بخطوة.

**Repo:** https://github.com/abdelouahabmostafaetu-bot/web-public-security-scanner  
**Version:** 1.2.0

## ماذا تفحص v1.2؟

1. HTTPS  
2. CSP / meta  
3. الأصول + Service Worker  
4. مكتبات JS الشائعة (إشارة فقط)  
5. روابط API/Backend  
6. Firebase + projectId hints من التخزين  
7. أسرار/مفاتيح في السورس وروابط الصفحة  
8. **PDF / Storage / blob + أزرار تحميل/طباعة**  
9. **الحساب / VIP / auth في localStorage**  
10. **JWT في التخزين**  
11. النماذج وكلمات المرور  
12. روابط target=_blank / javascript:  
13. الكوكيز الظاهرة  
14. Paywall UI  
15. Mixed content  
16. الملخص + تصدير JSON  

## التثبيت

```bash
git clone https://github.com/abdelouahabmostafaetu-bot/web-public-security-scanner.git
```

1. `chrome://extensions` → Developer mode  
2. Load unpacked → مجلد `extension/`  
3. بعد كل تحديث: زر **Reload** ثم امسح/أعد فتح الموقع وامسح  

## كيف تضيف اختبارات أكثر؟

1. أضف خطوة في `popup.js` → `STEP_DEFS`  
2. اكتب الفحص في `content.js` → `runScan()`  
3. `timeline.push` + `findings.push`  
4. ارفع النسخة  

### أفكار من GitHub (ملهمة وليست نسخًا)
- [RetireJS/retire.js](https://github.com/RetireJS/retire.js) — مكتبات JS قديمة  
- [momenbasel/keyFinder](https://github.com/momenbasel/keyFinder) — أسرار في storage/network  
- [bountyyfi/lonkero](https://github.com/bountyyfi/lonkero) — JWT + endpoints  
- [yipjunkai/secrets-spotter](https://github.com/yipjunkai/secrets-spotter) — اعتراض fetch/XHR  

## مهم
- لا تخترق ولا تتجاوز اشتراكات الغير  
- Firebase projectId ظاهر ≠ قراءة كل الملفات  
- الحماية = Auth + Security Rules  

## License
MIT
