'use client';

import Link from 'next/link';
import { useLanguage } from '../context/LanguageContext';

export function HeaderBar() {
  const { lang, toggleLanguage, t } = useLanguage();
  return (
    <header className="site-header">
      <Link href="/" className="brand">
        <svg className="brand-mark" width="40" height="40" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 2.5l8 3.4v6.3c0 5-3.4 8.4-8 10.3-4.6-1.9-8-5.3-8-10.3V5.9z" fill="currentColor" />
        </svg>
        <div>
          <span className="brand-name" dir="ltr">MobileShield</span>
          <span className="brand-tagline">{t.headerTagline}</span>
        </div>
      </Link>
      {/* The accessible name starts with the visible word (WCAG 2.5.3, label in name). */}
      <button type="button" className="language-button" onClick={toggleLanguage}>
        <span lang={lang === 'he' ? 'en' : 'he'} dir="auto">{lang === 'he' ? 'English' : 'עברית'}</span>
        <span className="sr-only">, {t.language}</span>
      </button>
    </header>
  );
}
