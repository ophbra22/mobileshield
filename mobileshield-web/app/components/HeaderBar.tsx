'use client';

import { Shield, Languages } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';

export function HeaderBar() {
  const { lang, toggleLanguage, t } = useLanguage();
  return <header className="site-header">
    <div className="brand"><span className="brand-mark"><Shield size={21} aria-hidden="true" /></span><div><p className="brand-name" dir="ltr">MobileShield</p><p className="brand-tagline">{t.headerTagline}</p></div></div>
    <button type="button" className="language-button" onClick={toggleLanguage} aria-label={t.language}><Languages size={17} aria-hidden="true" /><span lang={lang === 'he' ? 'en' : 'he'} dir="auto">{lang === 'he' ? 'EN' : 'עברית'}</span></button>
  </header>;
}
