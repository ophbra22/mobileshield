/**
 * Legal and accessibility pages. Every statement here describes what the code
 * actually does; update this file whenever data handling changes.
 */
export type Inline = string | { href: string; text: string };
export type Block =
  | { p: Inline[] }
  | { list: Inline[][] }
  | { table: { head: string[]; rows: string[][] } };
export interface LegalSection { heading: string; blocks: Block[] }
export interface LegalDoc { title: string; intro: Inline[]; sections: LegalSection[] }
export type LegalPageId = 'privacy' | 'cookies' | 'terms' | 'accessibility';

export const LAST_UPDATED = { he: '11 בנובמבר 2026', en: 'November 11, 2026' };
const OPERATOR = 'Ophir Braude';
const EMAIL = 'MobileShield@gmail.com';
const mail = { href: `mailto:${EMAIL}`, text: EMAIL };
const PPA_HE = { href: 'https://www.gov.il/he/departments/the_privacy_protection_authority', text: 'הרשות להגנת הפרטיות' };
const PPA_EN = { href: 'https://www.gov.il/en/departments/the_privacy_protection_authority', text: 'Privacy Protection Authority' };

export const LEGAL: Record<LegalPageId, { he: LegalDoc; en: LegalDoc }> = {
  privacy: {
    he: {
      title: 'מדיניות פרטיות',
      intro: ['MobileShield בודק הודעות חשודות ומסביר את סימני האזהרה שבהן. בנינו את השירות כך שיאסוף כמה שפחות מידע. כאן מוסבר בדיוק מה קורה למידע, בהתאם לחוק הגנת הפרטיות, התשמ״א–1981, כפי שתוקן בתיקון 13.'],
      sections: [
        { heading: 'מי מפעיל את האתר', blocks: [
          { p: [`האתר מופעל באופן פרטי על ידי ${OPERATOR}, שאחראי למידע שמעובד בו. לכל שאלה או בקשה בנושא פרטיות: `, mail, '.'] },
        ] },
        { heading: 'איזה מידע נאסף ולמה', blocks: [
          { list: [
            ['תוכן ההודעה שאתם מדביקים, כולל הקישורים שבה. המטרה היחידה היא לבדוק את ההודעה ולהציג לכם את התוצאה. ההודעה מעובדת בזיכרון השרת רק למשך הבדיקה. היא לא נשמרת במאגר מידע, לא נכתבת ביומני השרת ולא משמשת לשום מטרה אחרת, כולל אימון מודלים.'],
            ['כתובת ה־IP שלכם. משמשת רק כדי להגביל את מספר הבדיקות בדקה ולמנוע שימוש לרעה. היא נשמרת בזיכרון השרת עד דקה אחת ונמחקת, ואינה נכתבת ביומנים.'],
            ['יומני השרת כוללים רק את סוג הבקשה, קוד התוצאה, משך הטיפול ומזהה אקראי. הם לא כוללים את תוכן ההודעה, קישורים או כתובת IP.'],
            ['העדפת השפה נשמרת במכשיר שלכם בלבד, ורק אם אישרתם. הפרטים מופיעים במדיניות העוגיות והאחסון.'],
          ] },
        ] },
        { heading: 'בדיקת דפי הקישורים (לבחירתכם)', blocks: [
          { p: ['כברירת מחדל, הדפים שבקישורים לא נפתחים. אם תבחרו לבדוק גם אותם, השרת שלנו ייגש לכתובות שבהודעה. האתר המקושר יראה פנייה מהשרת שלנו ולא מהמכשיר שלכם. עם זאת, קישור אישי או חד־פעמי עלול להיחשב כקישור שנפתח, ולכן האפשרות כבויה כברירת מחדל.'] },
        ] },
        { heading: 'האם חובה למסור מידע', blocks: [
          { p: ['אין חובה חוקית למסור לנו מידע כלשהו. בלי ההודעה לא נוכל לבדוק אותה. לפני ההדבקה, מומלץ להסיר פרטים אישיים שאין צורך לבדוק, כמו שמות, מספרי חשבון או כתובות.'] },
        ] },
        { heading: 'למי מועבר המידע', blocks: [
          { p: ['אנחנו לא מוכרים, משכירים או מעבירים מידע לאף אחד. האתר מאוחסן אצל ספק ענן, שמעביר את התעבורה כחלק מהשירות שהוא נותן לנו. הספק עשוי לשמור יומני גישה טכניים, כמו כתובת IP ושעה, לפי המדיניות שלו. ייתכן שנידרש למסור מידע לפי דין, אבל מכיוון שאיננו שומרים את תוכן ההודעות, אין לנו תוכן כזה למסור.'] },
        ] },
        { heading: 'אבטחת מידע', blocks: [
          { p: ['התקשורת עם האתר מוצפנת (HTTPS), ותוכן ההודעות לא נשמר. בדיקת הקישורים חסומה בפני כתובות ברשתות פנימיות. אף מערכת אינה חסינה לחלוטין, ולכן אנחנו מצמצמים מראש את המידע שנאסף.'] },
        ] },
        { heading: 'הזכויות שלכם', blocks: [
          { p: ['לפי חוק הגנת הפרטיות, אתם רשאים לבקש לעיין במידע עליכם ולבקש לתקן או למחוק אותו. מכיוון שאיננו שומרים את תוכן ההודעות, בדרך כלל לא יהיה מידע לעיין בו. אפשר לפנות אלינו בכל שאלה בכתובת ', mail, '. אם אינכם מרוצים מהמענה, אפשר לפנות אל ', PPA_HE, '.'] },
        ] },
        { heading: 'שינויים במדיניות', blocks: [
          { p: ['אם נשנה את המדיניות, נעדכן את התאריך בראש העמוד.'] },
        ] },
      ],
    },
    en: {
      title: 'Privacy policy',
      intro: ['MobileShield checks suspicious messages and explains their warning signs. We built it to collect as little as possible. This page explains exactly what happens to data, in line with the Israeli Protection of Privacy Law, 5741-1981, as amended by Amendment 13.'],
      sections: [
        { heading: 'Who runs this site', blocks: [
          { p: [`This site is run privately by ${OPERATOR}, who is responsible for the data it processes. For any privacy question or request: `, mail, '.'] },
        ] },
        { heading: 'What is collected and why', blocks: [
          { list: [
            ['The message you paste, including its links. It is used only to check the message and show you the result. It is processed in server memory for the duration of the check. It is not stored in a database, not written to server logs, and not used for anything else, including model training.'],
            ['Your IP address. It is used only to limit the number of checks per minute and prevent abuse. It is kept in server memory for up to one minute and then removed, and it is not written to logs.'],
            ['Server logs contain only the request type, result code, duration and a random ID. They contain no message text, links or IP addresses.'],
            ['Your language preference is saved only on your device, and only if you allow it. See the cookie and storage policy.'],
          ] },
        ] },
        { heading: 'Inspecting linked pages (optional)', blocks: [
          { p: ['By default, linked pages are not opened. If you choose to inspect them, our server visits the addresses in the message. The linked site sees a request from our server, not from your device. A personal or one-time link may still count as opened, which is why this option is off by default.'] },
        ] },
        { heading: 'Do you have to provide data', blocks: [
          { p: ['There is no legal obligation to give us any data. Without a message, we cannot check it. Before pasting, we recommend removing personal details that do not need checking, such as names, account numbers or addresses.'] },
        ] },
        { heading: 'Who data is shared with', blocks: [
          { p: ['We do not sell, rent or share data with anyone. The site is hosted by a cloud provider that carries the traffic as part of its service to us. The provider may keep technical access logs, such as IP address and time, under its own policy. We may be required to disclose data by law, but because we do not keep message content, we have none to disclose.'] },
        ] },
        { heading: 'Security', blocks: [
          { p: ['Connections to the site are encrypted (HTTPS), and message content is not stored. Link inspection is blocked from reaching internal networks. No system is completely secure, which is why we keep collection to a minimum.'] },
        ] },
        { heading: 'Your rights', blocks: [
          { p: ['Under the Protection of Privacy Law, you may ask to see data about you and to correct or delete it. Because we do not keep message content, there is usually nothing to see. Contact us with any question at ', mail, '. If you are not satisfied with the answer, you can contact the ', PPA_EN, '.'] },
        ] },
        { heading: 'Changes', blocks: [
          { p: ['If we change this policy, we will update the date at the top of this page.'] },
        ] },
      ],
    },
  },

  cookies: {
    he: {
      title: 'מדיניות עוגיות ואחסון',
      intro: ['האתר לא משתמש בעוגיות (cookies) בכלל: לא לפרסום, לא לסטטיסטיקה ולא למעקב. אין באתר סקריפטים של צד שלישי, והגופן נטען מהאתר עצמו.'],
      sections: [
        { heading: 'מה כן נשמר במכשיר', blocks: [
          { p: ['האתר משתמש באחסון המקומי של הדפדפן (localStorage) לשני פריטים בלבד. הם לא נשלחים לשרת.'] },
          { table: {
            head: ['שם', 'מה זה', 'סוג', 'כמה זמן'],
            rows: [
              ['ms_storage_choice', 'הבחירה שלכם בהודעת האחסון (אישור או סירוב), כדי שלא נשאל שוב', 'חיוני', 'עד שתמחקו את נתוני האתר בדפדפן'],
              ['ms_lang', 'שפת התצוגה שבחרתם', 'אופציונלי, נשמר רק אחרי אישור', 'עד שתבחרו "לא לשמור" או תמחקו את נתוני האתר'],
            ],
          } },
        ] },
        { heading: 'איך משנים את הבחירה', blocks: [
          { p: ['לחצו על "הגדרות אחסון" בתחתית כל עמוד. בחירה ב"לא לשמור" מוחקת מיד את העדפת השפה. אפשר גם למחוק את נתוני האתר בהגדרות הדפדפן.'] },
        ] },
        { heading: 'מה לא נשמר', blocks: [
          { p: ['תוכן ההודעות ותוצאות הבדיקה לא נשמרים, לא במכשיר ולא בשרת. הם נעלמים כשסוגרים או מרעננים את הדף.'] },
        ] },
      ],
    },
    en: {
      title: 'Cookie and storage policy',
      intro: ['This site uses no cookies at all: none for advertising, analytics or tracking. There are no third-party scripts, and the font is served from the site itself.'],
      sections: [
        { heading: 'What is saved on your device', blocks: [
          { p: ['The site uses your browser\'s local storage (localStorage) for two items only. Neither is sent to the server.'] },
          { table: {
            head: ['Name', 'What it is', 'Type', 'How long'],
            rows: [
              ['ms_storage_choice', 'Your answer to the storage notice (allow or do not save), so we do not ask again', 'Essential', 'Until you clear this site\'s data in your browser'],
              ['ms_lang', 'The display language you chose', 'Optional, saved only after you allow it', 'Until you choose "Do not save" or clear this site\'s data'],
            ],
          } },
        ] },
        { heading: 'How to change your choice', blocks: [
          { p: ['Select "Storage settings" at the bottom of any page. Choosing "Do not save" deletes the language preference immediately. You can also clear this site\'s data in your browser settings.'] },
        ] },
        { heading: 'What is not saved', blocks: [
          { p: ['Messages and results are not saved, neither on your device nor on the server. They are gone when you close or reload the page.'] },
        ] },
      ],
    },
  },

  terms: {
    he: {
      title: 'תנאי שימוש',
      intro: ['MobileShield הוא כלי חינמי שבודק הודעות ומסמן סימני אזהרה לפישינג ולהונאה. השימוש באתר מהווה הסכמה לתנאים אלה.'],
      sections: [
        { heading: 'אין הבטחה לבטיחות', blocks: [
          { p: ['הבדיקה אוטומטית ומבוססת על כללים. היא עלולה לפספס הונאה חדשה או מתוחכמת, ולפעמים לסמן הודעה תקינה כחשודה. התוצאה היא כלי עזר בלבד, ואינה ייעוץ משפטי, פיננסי או ביטחוני. לפני פעולה כמו תשלום או מסירת פרטים, אמתו מול הארגון בדרך שאתם כבר מכירים.'] },
        ] },
        { heading: 'שימוש מותר', blocks: [
          { p: ['אפשר להשתמש באתר כדי לבדוק הודעות שקיבלתם. אסור:'] },
          { list: [
            ['לשלוח בקשות אוטומטיות בכמויות גדולות או לנסות לעקוף את הגבלת הקצב.'],
            ['להשתמש בבדיקת הקישורים כדי לסרוק אתרים של אחרים, לתקוף אותם או להעמיס עליהם.'],
            ['לנסות לפגוע באתר, בשרתים שלו או באבטחה שלו.'],
            ['להדביק מידע אישי של אחרים כשאין לכם רשות לשתף אותו.'],
          ] },
        ] },
        { heading: 'אחריות', blocks: [
          { p: ['השירות ניתן ללא תשלום, כמות שהוא (AS IS). ככל שהדין מאפשר, מפעיל האתר לא יישא באחריות לנזק שנגרם מהסתמכות על תוצאת בדיקה, מתקלה או מהפסקה בשירות.'] },
        ] },
        { heading: 'שינויים בשירות ובתנאים', blocks: [
          { p: ['אנחנו רשאים לשנות, להשהות או להפסיק את השירות או חלקים ממנו, ולעדכן את התנאים. התאריך בראש העמוד מציין את העדכון האחרון.'] },
        ] },
        { heading: 'קוד פתוח', blocks: [
          { p: ['קוד המקור של האתר מופץ ברישיון MIT.'] },
        ] },
        { heading: 'פרטיות', blocks: [
          { p: ['השימוש במידע מתואר במדיניות הפרטיות ובמדיניות העוגיות והאחסון.'] },
        ] },
        { heading: 'דין וסמכות שיפוט', blocks: [
          { p: ['על תנאים אלה חל הדין הישראלי. סמכות השיפוט נתונה לבתי המשפט המוסמכים בישראל.'] },
        ] },
        { heading: 'יצירת קשר', blocks: [
          { p: [`מפעיל האתר: ${OPERATOR}. דוא״ל: `, mail, '.'] },
        ] },
      ],
    },
    en: {
      title: 'Terms of use',
      intro: ['MobileShield is a free tool that checks messages and flags warning signs of phishing and fraud. By using the site you agree to these terms.'],
      sections: [
        { heading: 'No safety guarantee', blocks: [
          { p: ['Checks are automatic and rule-based. They can miss new or sophisticated scams and sometimes flag a legitimate message. The result is a decision aid only, not legal, financial or security advice. Before paying or sharing details, verify with the organization through a contact method you already trust.'] },
        ] },
        { heading: 'Acceptable use', blocks: [
          { p: ['You may use the site to check messages you received. You may not:'] },
          { list: [
            ['Send automated requests in bulk or try to get around the rate limit.'],
            ['Use link inspection to scan, attack or overload other people\'s sites.'],
            ['Try to harm the site, its servers or its security.'],
            ['Paste other people\'s personal data you are not allowed to share.'],
          ] },
        ] },
        { heading: 'Liability', blocks: [
          { p: ['The service is free and provided "as is". To the extent the law allows, the operator is not liable for damage caused by relying on a result, by a fault, or by an interruption of the service.'] },
        ] },
        { heading: 'Changes', blocks: [
          { p: ['We may change, suspend or end the service or parts of it, and update these terms. The date at the top of this page shows the latest update.'] },
        ] },
        { heading: 'Open source', blocks: [
          { p: ['The site\'s source code is released under the MIT license.'] },
        ] },
        { heading: 'Privacy', blocks: [
          { p: ['How data is used is described in the privacy policy and the cookie and storage policy.'] },
        ] },
        { heading: 'Governing law', blocks: [
          { p: ['These terms are governed by Israeli law. The competent courts in Israel have jurisdiction.'] },
        ] },
        { heading: 'Contact', blocks: [
          { p: [`Operator: ${OPERATOR}. Email: `, mail, '.'] },
        ] },
      ],
    },
  },

  accessibility: {
    he: {
      title: 'הצהרת נגישות',
      intro: ['אנחנו רוצים שכל אחד יוכל לבדוק הודעה חשודה בעצמו, כולל אנשים עם מוגבלות ומבוגרים. האתר נבנה מההתחלה כך שיהיה קל לקריאה ולשימוש.'],
      sections: [
        { heading: 'רמת הנגישות', blocks: [
          { p: ['האתר הותאם לתקנות שוויון זכויות לאנשים עם מוגבלות (התאמות נגישות לשירות), התשע״ג–2013, ולתקן הישראלי ת״י 5568, המבוסס על הנחיות WCAG ברמה AA. אנחנו בודקים את האתר מול WCAG 2.1 ברמה AA.'] },
        ] },
        { heading: 'מה עשינו', blocks: [
          { list: [
            ['טקסט גדול, ותשובה במשפט אחד בשפה פשוטה.'],
            ['ניגודיות של 5:1 לפחות לכל טקסט, ו־3:1 לפחות לגבולות של כפתורים ושדות.'],
            ['צבעי התשובה שונים זה מזה גם בבהירות ולא רק בגוון, כך שאפשר להבחין ביניהם גם עם עיוורון צבעים. כל תשובה מלווה גם בסמל ובמשפט.'],
            ['כפתורים גדולים עם תוויות טקסט ברורות, ואזור לחיצה של 44 פיקסלים לפחות.'],
            ['ניווט מלא במקלדת, קישור "דילוג לתוכן" ומסגרת מיקוד בולטת.'],
            ['תמיכה בקוראי מסך: כותרות מסודרות, תוויות לשדות, והודעה אוטומטית כשהתוצאה מוכנה.'],
            ['התאמה להגדלת תצוגה ולמסכים צרים של עד 320 פיקסלים, בלי גלילה לרוחב.'],
            ['עברית מימין לשמאל ואנגלית משמאל לימין, ושפת הדף מוגדרת בהתאם.'],
            ['כיבוד הגדרות המערכת להפחתת תנועה ולניגודיות גבוהה.'],
            ['בלי תוסף נגישות חיצוני: ההתאמות בנויות באתר עצמו.'],
          ] },
        ] },
        { heading: 'איך בדקנו', blocks: [
          { p: ['בכל שינוי בקוד רצות בדיקות נגישות אוטומטיות (axe-core) ובדיקות בדפדפנים Chrome, Firefox ו־Safari במחשב, בטאבלט ובטלפון. נבדקה גם עבודה עם מקלדת בלבד.'] },
        ] },
        { heading: 'מגבלות ידועות', blocks: [
          { list: [
            ['האתר בודק הודעות בעברית ובאנגלית בלבד.'],
            ['תוכן האתרים שאליהם מובילים הקישורים בהודעות אינו בשליטתנו.'],
            ['האתר עדיין לא נבדק על ידי מורשה נגישות שירות.'],
          ] },
        ] },
        { heading: 'נתקלתם בבעיה?', blocks: [
          { p: ['אם משהו באתר לא נגיש לכם, נשמח לדעת ולתקן. רכז הנגישות: ', OPERATOR, ', דוא״ל: ', mail, '. כדי שנוכל לעזור, ציינו באיזה דף מדובר, מה ניסיתם לעשות, ובאיזה דפדפן ובאיזו טכנולוגיה מסייעת השתמשתם.'] },
        ] },
      ],
    },
    en: {
      title: 'Accessibility statement',
      intro: ['We want everyone to be able to check a suspicious message on their own, including people with disabilities and older users. The site was built from the start to be easy to read and use.'],
      sections: [
        { heading: 'Conformance', blocks: [
          { p: ['The site was adapted to the Israeli Equal Rights for Persons with Disabilities (Service Accessibility Adjustments) Regulations, 5773-2013, and to Israeli Standard IS 5568, which is based on WCAG at level AA. We test the site against WCAG 2.1 level AA.'] },
        ] },
        { heading: 'What we did', blocks: [
          { list: [
            ['Large text, and a one-sentence answer in plain language.'],
            ['At least 5:1 contrast for all text, and at least 3:1 for button and field borders.'],
            ['Verdict colors differ in lightness as well as hue, so they can be told apart with color blindness. Every verdict also has an icon and a sentence.'],
            ['Large buttons with clear text labels, and touch targets of at least 44 pixels.'],
            ['Full keyboard navigation, a "Skip to content" link and a clearly visible focus outline.'],
            ['Screen reader support: ordered headings, labelled fields, and an automatic announcement when the result is ready.'],
            ['Works with zoom and on narrow screens down to 320 pixels, without horizontal scrolling.'],
            ['Hebrew right to left and English left to right, with the page language set to match.'],
            ['Respects system settings for reduced motion and high contrast.'],
            ['No third-party accessibility overlay: the adjustments are built into the site.'],
          ] },
        ] },
        { heading: 'How we tested', blocks: [
          { p: ['Every code change runs automated accessibility checks (axe-core) and tests in Chrome, Firefox and Safari on desktop, tablet and phone. Keyboard-only use was also tested.'] },
        ] },
        { heading: 'Known limitations', blocks: [
          { list: [
            ['Messages can be checked in Hebrew and English only.'],
            ['The content of sites that links in messages lead to is outside our control.'],
            ['The site has not yet been reviewed by a certified accessibility auditor.'],
          ] },
        ] },
        { heading: 'Found a problem?', blocks: [
          { p: ['If anything on the site is not accessible to you, please tell us so we can fix it. Accessibility coordinator: ', OPERATOR, ', email: ', mail, '. To help us, mention the page, what you tried to do, and which browser and assistive technology you used.'] },
        ] },
      ],
    },
  },
};
