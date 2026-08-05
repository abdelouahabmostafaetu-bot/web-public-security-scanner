# شرح فحوصات الثغرات (عربي)

## ماذا تعني المستويات؟
- **High**: يستحق اهتمام فوري (HTTPS غائب، أسرار قوية، mixed content، eval…)
- **Medium**: راجع يدويًا (VIP في localStorage، sinks XSS، admin paths، PDF عام)
- **Low/Info**: ملاحظات / سياق

## فحوصات جديدة v1.3
1. **DOM XSS sinks**: innerHTML/document.write… وجودها ≠ ثغرة، لكن خطر إن دخلت مدخلات مستخدم.
2. **eval/new Function**: تنفيذ نص ككود — خطر إن تأثر بمدخل خارجي.
3. **Admin paths**: /admin /debug /.env في السورس.
4. **Source maps**: قد تكشف الكود الأصلي.
5. **Emails/phones**: بيانات ظاهرة.
6. **Iframes**: طرف ثالث / sandbox.
7. **Open redirect params**: ?next=https://...

## Firebase API key
مفتاح `AIza...` العام طبيعي. ليس Admin SDK. الحماية = Rules.

## VIP localStorage
`was_vip=false` يعني الواجهة تعرف أنك غير مشترك. الحماية الحقيقية من السيرفر.

## PDF
لا رابط مباشر + print = طبيعي للمحتوى المجاني.
