'use client';

import Link from 'next/link';
import { useLanguage } from '../context/LanguageContext';

export function HeaderBar() {
  const { lang, toggleLanguage, t } = useLanguage();
  return (
    <header className="site-header">
      <Link href="/" className="brand">
        <span className="brand-mark" aria-hidden="true"><span /><span /></span>
        <div>
          <span className="brand-name" dir="ltr">PauseCheck</span>
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
