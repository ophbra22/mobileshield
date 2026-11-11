'use client';

import Link from 'next/link';
import { useEffect } from 'react';
import { HeaderBar } from './HeaderBar';
import { SiteFooter } from './SiteFooter';
import { useLanguage } from '../context/LanguageContext';
import { LAST_UPDATED, LEGAL, type Inline, type LegalPageId } from '../legal/content';

function Text({ parts }: { parts: Inline[] }) {
  return <>{parts.map((part, index) => typeof part === 'string'
    ? <span key={index}>{part}</span>
    : <a key={index} href={part.href} {...(part.href.startsWith('http') ? { target: '_blank', rel: 'noopener noreferrer' } : {})}>
        <bdi>{part.text}</bdi>
      </a>)}</>;
}

export function LegalPage({ id }: { id: LegalPageId }) {
  const { lang, t } = useLanguage();
  const doc = LEGAL[id][lang];
  useEffect(() => { document.title = `${doc.title} | MobileShield`; }, [doc.title]);
  return (
    <div className="site-shell">
      <a className="skip-link" href="#main-content">{t.skipToContent}</a>
      <HeaderBar />
      <main id="main-content" className="main-content legal">
        <Link href="/" className="back-link">{t.backHome}</Link>
        <h1>{doc.title}</h1>
        <p className="legal-updated">{t.lastUpdated}: {LAST_UPDATED[lang]}</p>
        <p className="legal-intro"><Text parts={doc.intro} /></p>
        {doc.sections.map(section => (
          <section key={section.heading} className="legal-section">
            <h2>{section.heading}</h2>
            {section.blocks.map((block, index) => {
              if ('p' in block) return <p key={index}><Text parts={block.p} /></p>;
              if ('list' in block) return <ul key={index}>{block.list.map((item, i) => <li key={i}><Text parts={item} /></li>)}</ul>;
              return (
                <div key={index} className="table-scroll" role="region" aria-label={section.heading} tabIndex={0}>
                  <table>
                    <thead><tr>{block.table.head.map(cell => <th key={cell} scope="col">{cell}</th>)}</tr></thead>
                    <tbody>{block.table.rows.map(row => (
                      <tr key={row[0]}>{row.map((cell, i) => i === 0
                        ? <th key={i} scope="row"><code dir="ltr">{cell}</code></th>
                        : <td key={i}>{cell}</td>)}</tr>
                    ))}</tbody>
                  </table>
                </div>
              );
            })}
          </section>
        ))}
      </main>
      <SiteFooter />
    </div>
  );
}
