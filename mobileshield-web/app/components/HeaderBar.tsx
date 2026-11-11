'use client';

import { useLanguage } from '../context/LanguageContext';

export function HeaderBar() {
  const { lang, toggleLanguage, t } = useLanguage();
  return (
    <header className="site-header">
      <div className="brand">
        <svg className="brand-mark" width="40" height="40" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 2.5l8 3.4v6.3c0 5-3.4 8.4-8 10.3-4.6-1.9-8-5.3-8-10.3V5.9z" fill="currentColor" />
        </svg>
        <div>
          <p className="brand-name" dir="ltr">MobileShield</p>
          <p className="brand-tagline">{t.headerTagline}</p>
        </div>
      </div>
      <button type="button" className="language-button" onClick={toggleLanguage} aria-label={t.language}>
        <span lang={lang === 'he' ? 'en' : 'he'} dir="auto">{lang === 'he' ? 'English' : 'עברית'}</span>
      </button>
    </header>
  );
}
