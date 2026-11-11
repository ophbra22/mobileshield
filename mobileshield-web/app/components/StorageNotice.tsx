'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { OPEN_SETTINGS_EVENT, readStorageChoice, writeStorageChoice, type StorageChoice } from '@/lib/consent';
import { useLanguage } from '../context/LanguageContext';

/**
 * A non-blocking notice: the site works fully before and after any choice.
 * Both answers have equal weight; nothing optional is stored until "Allow".
 */
export function StorageNotice() {
  const { t } = useLanguage();
  const [open, setOpen] = useState(false);
  const allowRef = useRef<HTMLButtonElement>(null);
  const reopened = useRef(false);

  useEffect(() => {
    setOpen(readStorageChoice() === null);
    const reopen = () => { reopened.current = true; setOpen(true); };
    window.addEventListener(OPEN_SETTINGS_EVENT, reopen);
    return () => window.removeEventListener(OPEN_SETTINGS_EVENT, reopen);
  }, []);

  useEffect(() => {
    // Only move focus when the visitor asked for the settings, never on page load.
    if (open && reopened.current) allowRef.current?.focus();
    document.body.classList.toggle('has-storage-notice', open);
  }, [open]);

  if (!open) return null;
  const choose = (choice: StorageChoice) => { writeStorageChoice(choice); reopened.current = false; setOpen(false); };
  return (
    <section className="storage-notice" aria-labelledby="storage-notice-title">
      <div className="storage-notice-inner">
        <div className="storage-notice-text">
          <h2 id="storage-notice-title">{t.noticeTitle}</h2>
          <p>{t.noticeText} <Link href="/cookies">{t.noticeMore}</Link></p>
        </div>
        <div className="storage-notice-actions">
          <button ref={allowRef} type="button" className="primary-button" onClick={() => choose('granted')}>{t.noticeAllow}</button>
          <button type="button" className="secondary-button" onClick={() => choose('denied')}>{t.noticeDeny}</button>
        </div>
      </div>
    </section>
  );
}
