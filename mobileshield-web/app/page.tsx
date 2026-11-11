'use client';

import { HeaderBar } from './components/HeaderBar';
import { ScanForm } from './components/ScanForm';
import { ResultDisplay } from './components/ResultDisplay';
import { useMessageAnalysis } from './hooks/useMessageAnalysis';
import { useLanguage } from './context/LanguageContext';

export default function Home() {
  const { state, submit, cancel, invalidate, retry } = useMessageAnalysis();
  const { t } = useLanguage();
  return (
    <div className="site-shell">
      <a className="skip-link" href="#main-content">{t.skipToContent}</a>
      <HeaderBar />
      <main id="main-content" className="main-content">
        <ScanForm onSubmit={request => void submit(request)} onInvalidate={invalidate} loading={state.status === 'loading'} />
        <ResultDisplay state={state} onCancel={cancel} onRetry={() => void retry()} />
      </main>
      <footer className="site-footer">
        <p>{t.footerNote}</p>
        <nav aria-label={t.contact}>
          <a href="mailto:MobileShield@gmail.com">{t.contact}</a>
          <a href="https://www.linkedin.com/in/ophir-braude-188252378/" target="_blank" rel="noopener noreferrer">LinkedIn</a>
          <a href="https://github.com/ophbra22/mobileshield" target="_blank" rel="noopener noreferrer">GitHub</a>
        </nav>
      </footer>
    </div>
  );
}
