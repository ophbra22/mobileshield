'use client';

import Link from 'next/link';
import { openStorageSettings } from '@/lib/consent';
import { useLanguage } from '../context/LanguageContext';

export function SiteFooter() {
  const { t } = useLanguage();
  return (
    <footer className="site-footer">
      <p>{t.footerNote}</p>
      <nav aria-label={t.legalNav} className="footer-legal">
        <Link href="/privacy">{t.privacy}</Link>
        <Link href="/cookies">{t.cookies}</Link>
        <Link href="/terms">{t.terms}</Link>
        <Link href="/accessibility">{t.accessibility}</Link>
        <button type="button" className="link-button" onClick={openStorageSettings}>{t.storageSettings}</button>
      </nav>
      <nav aria-label={t.contact} className="footer-contact">
        <a href="mailto:MobileShield@gmail.com">{t.contact}</a>
        <a href="https://www.linkedin.com/in/ophir-braude-188252378/" target="_blank" rel="noopener noreferrer">LinkedIn</a>
        <a href="https://github.com/ophbra22/mobileshield" target="_blank" rel="noopener noreferrer">GitHub</a>
      </nav>
    </footer>
  );
}
