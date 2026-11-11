'use client';

import { HeaderBar } from './components/HeaderBar';
import { SiteFooter } from './components/SiteFooter';
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
      <SiteFooter />
    </div>
  );
}
