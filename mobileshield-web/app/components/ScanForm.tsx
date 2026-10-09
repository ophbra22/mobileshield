'use client';

import { useEffect, useRef, useState } from 'react';
import { ClipboardPaste, ArrowUpRight, Search } from 'lucide-react';
import { MAX_TEXT_CODEPOINTS, validateMessageRequest } from '@/lib/analysis';
import type { MessageRequest } from '@/lib/analysis';
import { Textarea } from './ui/textarea';
import { useLanguage } from '../context/LanguageContext';

interface Props { onSubmit: (request: MessageRequest) => void; onInvalidate: () => void; loading: boolean }

export function ScanForm({ onSubmit, onInvalidate, loading }: Props) {
  const { t, lang } = useLanguage();
  const [text, setText] = useState('');
  const [inspectLinks, setInspectLinks] = useState(false);
  const [pasteDenied, setPasteDenied] = useState(false);
  const draftRevision = useRef(0);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => () => { draftRevision.current++; }, []);
  const count = Array.from(text).length;
  const overLimit = count > MAX_TEXT_CODEPOINTS;
  let valid = false;
  try { validateMessageRequest({ text, inspect_links: inspectLinks }); valid = true; } catch { /* Render draft without truncating. */ }
  function changeText(next: string) {
    draftRevision.current++;
    onInvalidate();
    setText(next);
    setPasteDenied(false);
  }
  async function paste() {
    const revision = ++draftRevision.current;
    try {
      const pasted = await navigator.clipboard.readText();
      if (revision !== draftRevision.current) return;
      changeText(pasted);
      inputRef.current?.focus();
    } catch {
      if (revision === draftRevision.current) setPasteDenied(true);
    }
  }
  return (
    <form className="card scan-card" onSubmit={event => { event.preventDefault(); if (valid && !loading) onSubmit({ text, inspect_links: inspectLinks }); }} aria-labelledby="form-title">
      <div className="card-heading"><Search size={20} aria-hidden="true" /><h2 id="form-title">{t.scanTitle}</h2><span className="step-tag" aria-hidden="true">01</span></div>
      <div className="input-heading">
        <label htmlFor="message-input">{t.messageLabel}</label>
        <div className="draft-actions">
          <button type="button" className="quiet-button" onClick={() => void paste()}><ClipboardPaste size={16} aria-hidden="true" />{t.paste}</button>
          <button type="button" className="quiet-button" onClick={() => { changeText(''); inputRef.current?.focus(); }}>{t.clear}</button>
        </div>
      </div>
      <Textarea id="message-input" ref={inputRef} dir={text.trim() ? 'auto' : lang === 'he' ? 'rtl' : 'ltr'} rows={7} value={text} onChange={event => changeText(event.target.value)} placeholder={t.placeholder}
        aria-describedby={`message-help message-count${overLimit ? ' message-limit' : ''}`} aria-invalid={overLimit} autoComplete="off" spellCheck={false} />
      <div className="input-meta"><p id="message-help">{t.inputHelp}</p><p id="message-count" className={overLimit ? 'count over-limit' : 'count'}><bdi dir="ltr">{count} / 10,000</bdi> {t.characterCount}</p></div>
      {overLimit && <p id="message-limit" className="field-notice">{t.overLimit}</p>}
      {pasteDenied && <p role="status" className="field-notice">{t.pasteDenied}</p>}
      <div className="inspection-choice">
        <input id="inspect-links" type="checkbox" checked={inspectLinks} aria-describedby="inspection-help" onChange={event => {
          draftRevision.current++; onInvalidate(); setInspectLinks(event.target.checked);
        }} />
        <div><label htmlFor="inspect-links">{t.inspectLabel}</label><p id="inspection-help">{t.inspectHelp}</p></div>
      </div>
      <div className="submit-row">
        <p>{t.staticHelp}</p>
        <button className="primary-button" type="submit" disabled={!valid || loading}>{t.scanButton}<ArrowUpRight size={18} aria-hidden="true" /></button>
      </div>
    </form>
  );
}
