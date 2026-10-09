'use client';

import { createContext, useContext, useEffect, useMemo, useState } from 'react';

type Lang = 'he' | 'en';
const translations = {
  en: {
    headerTagline: 'A second look before you act', language: 'Switch to Hebrew', contact: 'Contact us',
    eyebrow: 'PAUSE. CHECK. DECIDE.', title: 'Something feels off?', intro: 'Check a message for warning signs before you reply, share details or open a link.',
    scanTitle: 'Check the whole message', messageLabel: 'Message to check', placeholder: 'Paste the message here, including any links…',
    inputHelp: 'Include the wording and links. Remove personal details you do not need checked.', paste: 'Paste', clear: 'Clear',
    characterCount: 'characters', overLimit: 'The message exceeds 10,000 characters. Shorten it before checking.',
    pasteDenied: 'Clipboard unavailable. Paste or type your message manually.',
    inspectLabel: 'Inspect linked pages too', inspectHelp: 'Optional: the server visits supported public links and checks page content. This takes longer and may activate tracking or a one-time link at the destination. Off by default.',
    staticHelp: 'By default, only the message and link structure are checked; linked pages are not visited.',
    scanButton: 'Check message', checking: 'Checking message…', cancel: 'Cancel check', retry: 'Retry check',
    resultLabel: 'MESSAGE ASSESSMENT', resultContext: 'For the message you submitted', nextStep: 'What to do next', reasonsTitle: 'Why this assessment',
    noReasons: 'No specific warning evidence was returned.', coverageTitle: 'Check coverage',
    complete: 'Requested checks completed', partial: 'Analysis incomplete', unavailable: 'Analysis unavailable',
    partialHelp: 'Some requested checks could not finish. Any warning signs above still apply.', unavailableHelp: 'There is not enough completed analysis to draw a reliable conclusion.',
    noGuarantee: 'This is not a safety guarantee. New or subtle threats may go undetected.',
    errorTitle: 'Check could not finish', linkDetails: 'Link details', noLinks: 'No links were identified.', unknownHost: 'Unrecognized link',
    linkAssessment: 'Link assessment', normalizedDestination: 'Submitted destination', finalDestination: 'Final destination',
    maskedHelp: 'Private URL parts are hidden. Domains are shown as text so you can review them without opening a page.',
    assessments: { phishing: 'Phishing warning', suspicious: 'Suspicious signs', no_clear_signs: 'No clear warning signs', unknown: 'Unable to assess' },
    descriptions: { phishing: 'Strong warning signs were found. Pause before interacting with this message.', suspicious: 'This message has warning signs that deserve a closer look.', no_clear_signs: 'The completed checks did not find clear warning signs.', unknown: 'The available evidence does not support a reliable assessment.' },
    actions: {
      avoid_interaction: 'Avoid opening links, replying or following instructions in this message.',
      verify_independently: 'Verify with the organization using a contact method you already trust.',
      do_not_share_secrets: 'Do not share passwords, payment details or one-time codes.',
      consider_link_inspection: 'Consider optional link inspection for more information about linked pages.',
      retry_later: 'Try checking again later. Until then, pause and verify independently.',
    },
    reasons: {
      credential_request: 'The message asks for passwords or one-time codes.', payment_request: 'The message requests a payment or financial details.',
      urgency: 'Urgent or pressuring language was detected.', brand_destination_mismatch: 'A claimed organization does not match the link destination.',
      lookalike_host: 'A domain resembles a known organization but is different.', suspicious_obfuscation: 'The link structure may disguise its destination.',
      credential_form: 'The linked page contains sign-in or credential fields.', payment_form: 'The linked page contains payment fields.',
      local_blocklist_hit: 'The destination matches a local warning list.', certificate_mismatch: 'The destination certificate could not be verified.',
      unsupported_text: 'Some message text could not be assessed.', invalid_link: 'A link could not be parsed or supported.',
      inspection_disabled: 'Linked pages were not visited.', inspection_failed: 'A linked page inspection could not finish.',
      destination_blocked: 'A destination was blocked by inspection safeguards.', body_limit: 'A page exceeded the inspection size limit.',
      deadline_exceeded: 'The inspection time limit was reached.', unknown_reason: 'Some evidence could not be interpreted.',
    },
    inspection: { not_requested: 'Page not visited', completed: 'Page inspection completed', blocked: 'Destination blocked', failed: 'Page inspection failed', skipped: 'Page inspection skipped' },
    errors: {
      invalid_request: 'Enter a non-empty message of at most 10,000 characters, with at most 10 distinct links.',
      invalid_response: 'The response could not be verified. Try again later.', analysis_unavailable: 'Analysis is temporarily unavailable. Try again later.',
      rate_limit_exceeded: 'Too many checks were requested. Wait before trying again.', request_failed: 'The request could not finish. Try again later.',
      network_error: 'A connection could not be made. Check your connection and try again.', timeout: 'The check took too long. Try again later.', cancelled: 'The check was cancelled.',
    },
    footerNote: 'A check helps you decide. When in doubt, verify independently.',
  },
  he: {
    headerTagline: 'עוד מבט לפני שפועלים', language: 'מעבר לאנגלית', contact: 'יצירת קשר',
    eyebrow: 'עוצרים. בודקים. מחליטים.', title: 'משהו בהודעה מרגיש חשוד?', intro: 'בדקו סימני אזהרה בהודעה לפני שמשיבים, משתפים פרטים או פותחים קישור.',
    scanTitle: 'בודקים את ההודעה המלאה', messageLabel: 'הודעה לבדיקה', placeholder: 'הדביקו כאן את ההודעה, כולל הקישורים…',
    inputHelp: 'כללו את הניסוח ואת הקישורים. הסירו פרטים אישיים שאין צורך לבדוק.', paste: 'הדבקה', clear: 'ניקוי',
    characterCount: 'תווים', overLimit: 'ההודעה ארוכה מ־10,000 תווים. קצרו אותה לפני הבדיקה.',
    pasteDenied: 'הלוח אינו זמין. אפשר להדביק או להקליד את ההודעה ידנית.',
    inspectLabel: 'בדיקה גם של דפי הקישורים', inspectHelp: 'לבחירתכם: השרת מבקר בקישורים ציבוריים נתמכים ובודק את תוכן הדפים. הבדיקה אורכת יותר זמן ועלולה להפעיל מעקב או קישור חד־פעמי ביעד. כבוי כברירת מחדל.',
    staticHelp: 'כברירת מחדל נבדקים רק ההודעה ומבנה הקישורים; דפי הקישורים אינם נפתחים.',
    scanButton: 'בדיקת הודעה', checking: 'בודקים את ההודעה…', cancel: 'ביטול בדיקה', retry: 'בדיקה חוזרת',
    resultLabel: 'הערכת ההודעה', resultContext: 'עבור ההודעה ששלחתם', nextStep: 'מה כדאי לעשות', reasonsTitle: 'הסיבות להערכה',
    noReasons: 'לא התקבלו סימני אזהרה מסוימים.', coverageTitle: 'כיסוי הבדיקה',
    complete: 'הבדיקות שהתבקשו הושלמו', partial: 'הבדיקה לא הושלמה במלואה', unavailable: 'הבדיקה אינה זמינה',
    partialHelp: 'חלק מהבדיקות שהתבקשו לא הסתיימו. סימני אזהרה שמופיעים למעלה עדיין תקפים.', unavailableHelp: 'אין מספיק בדיקות שהושלמו כדי להגיע למסקנה מהימנה.',
    noGuarantee: 'אין כאן הבטחה לבטיחות. איומים חדשים או עדינים עלולים שלא להתגלות.',
    errorTitle: 'לא ניתן היה לסיים את הבדיקה', linkDetails: 'פרטי הקישורים', noLinks: 'לא זוהו קישורים.', unknownHost: 'קישור לא מזוהה',
    linkAssessment: 'הערכת הקישור', normalizedDestination: 'היעד שנשלח', finalDestination: 'היעד הסופי',
    maskedHelp: 'חלקים פרטיים בכתובת מוסתרים. שמות המתחם מוצגים כטקסט, כדי לבדוק אותם בלי לפתוח דף.',
    assessments: { phishing: 'אזהרת פישינג', suspicious: 'סימנים חשודים', no_clear_signs: 'לא נמצאו סימני אזהרה ברורים', unknown: 'לא ניתן להעריך' },
    descriptions: { phishing: 'נמצאו סימני אזהרה חזקים. עצרו לפני פעולה בעקבות ההודעה.', suspicious: 'בהודעה יש סימני אזהרה שכדאי לבדוק מקרוב.', no_clear_signs: 'בבדיקות שהושלמו לא נמצאו סימני אזהרה ברורים.', unknown: 'המידע הזמין אינו מספיק להערכה מהימנה.' },
    actions: {
      avoid_interaction: 'הימנעו מפתיחת קישורים, ממענה או מביצוע ההוראות בהודעה.',
      verify_independently: 'אמתו מול הארגון דרך אמצעי קשר שאתם כבר סומכים עליו.',
      do_not_share_secrets: 'אל תשתפו סיסמאות, פרטי תשלום או קודים חד־פעמיים.',
      consider_link_inspection: 'אפשר לבחור בבדיקת קישורים כדי לקבל מידע נוסף על הדפים.',
      retry_later: 'נסו לבדוק שוב מאוחר יותר. בינתיים עצרו ואמתו באופן עצמאי.',
    },
    reasons: {
      credential_request: 'ההודעה מבקשת סיסמאות או קודים חד־פעמיים.', payment_request: 'ההודעה מבקשת תשלום או פרטים פיננסיים.',
      urgency: 'זוהה ניסוח דחוף או לוחץ.', brand_destination_mismatch: 'הארגון המוזכר אינו תואם ליעד הקישור.',
      lookalike_host: 'שם המתחם דומה לארגון מוכר, אך שונה ממנו.', suspicious_obfuscation: 'מבנה הקישור עלול להסתיר את היעד שלו.',
      credential_form: 'בדף המקושר יש שדות כניסה או מסירת פרטי גישה.', payment_form: 'בדף המקושר יש שדות תשלום.',
      local_blocklist_hit: 'היעד מופיע ברשימת אזהרות מקומית.', certificate_mismatch: 'לא ניתן היה לאמת את תעודת האבטחה של היעד.',
      unsupported_text: 'לא ניתן היה להעריך חלק מטקסט ההודעה.', invalid_link: 'לא ניתן היה לפענח קישור או לתמוך בו.',
      inspection_disabled: 'דפי הקישורים לא נפתחו.', inspection_failed: 'בדיקה של דף מקושר לא הסתיימה.',
      destination_blocked: 'יעד נחסם על ידי מנגנוני ההגנה של הבדיקה.', body_limit: 'דף חרג ממגבלת הגודל לבדיקה.',
      deadline_exceeded: 'הבדיקה הגיעה למגבלת הזמן.', unknown_reason: 'לא ניתן היה לפרש חלק מהמידע.',
    },
    inspection: { not_requested: 'הדף לא נפתח', completed: 'בדיקת הדף הושלמה', blocked: 'היעד נחסם', failed: 'בדיקת הדף נכשלה', skipped: 'בדיקת הדף דולגה' },
    errors: {
      invalid_request: 'הזינו הודעה שאינה ריקה, עד 10,000 תווים ועד 10 קישורים שונים.',
      invalid_response: 'לא ניתן היה לאמת את התשובה. נסו שוב מאוחר יותר.', analysis_unavailable: 'הבדיקה אינה זמינה כרגע. נסו שוב מאוחר יותר.',
      rate_limit_exceeded: 'התבקשו יותר מדי בדיקות. המתינו לפני ניסיון נוסף.', request_failed: 'הבקשה לא הסתיימה. נסו שוב מאוחר יותר.',
      network_error: 'לא ניתן היה להתחבר. בדקו את החיבור ונסו שוב.', timeout: 'הבדיקה ארכה זמן רב מדי. נסו שוב מאוחר יותר.', cancelled: 'הבדיקה בוטלה.',
    },
    footerNote: 'הבדיקה עוזרת להחליט. כשיש ספק, אמתו באופן עצמאי.',
  },
} as const;

type LanguageContextType = { lang: Lang; t: (typeof translations)[Lang]; toggleLanguage: () => void; setLanguage: (lang: Lang) => void };
const LanguageContext = createContext<LanguageContextType | undefined>(undefined);
export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLang] = useState<Lang>('he');
  useEffect(() => {
    // Only the language preference is stored; message drafts and results are not.
    try { const saved = localStorage.getItem('ms_lang'); if (saved === 'he' || saved === 'en') setLang(saved); } catch { /* Preference storage is optional. */ }
  }, []);
  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'he' ? 'rtl' : 'ltr';
    try { localStorage.setItem('ms_lang', lang); } catch { /* Manual language switching still works. */ }
  }, [lang]);
  const value = useMemo(() => ({ lang, t: translations[lang], toggleLanguage: () => setLang(prev => prev === 'he' ? 'en' : 'he'), setLanguage: setLang }), [lang]);
  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}
export function useLanguage() {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error('useLanguage must be used within LanguageProvider');
  return ctx;
}
export const getTranslations = (lang: Lang) => translations[lang];
