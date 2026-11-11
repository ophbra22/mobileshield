'use client';

import { AlertCircle, AlertTriangle, Check, HelpCircle, Loader2, SearchCheck, X } from 'lucide-react';
import type { MessageAnalysisState } from '../hooks/useMessageAnalysis';
import type { Reason } from '@/lib/analysis';
import { useLanguage } from '../context/LanguageContext';

interface Props {
  state: MessageAnalysisState;
  onCancel: () => void;
  onRetry: () => void;
}

/** Show only the origin; credentials, paths, queries and fragments stay hidden. */
function maskedDestination(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return `${url.protocol}//${url.host}/…`;
  } catch {
    return null;
  }
}

function hasOnlyTextLimitation(state: MessageAnalysisState) {
  return state.status === 'result' && state.result.assessment === 'unknown'
    && state.result.analysis_status === 'unavailable'
    && state.result.limitations.length === 1 && state.result.limitations[0] === 'unsupported_text';
}

function ResultContent({ state, onCancel, onRetry }: Props) {
  const { t } = useLanguage();
  const reasonCopy = (code: string) => t.reasons[code as keyof typeof t.reasons] ?? t.reasons.unknown_reason;
  const reasonList = (reasons: Reason[], marked = false) => (
    <ul className={marked ? 'evidence-list marked-list' : 'evidence-list'}>
      {Array.from(new Set(reasons.map(reason => reason.code))).map(code => (
        <li key={code}>{marked && <X className="list-icon" size={26} aria-hidden="true" />}<span>{reasonCopy(code)}</span></li>
      ))}
    </ul>
  );
  if (state.status === 'idle') return null;
  if (state.status === 'loading') return (
    <section className="card pending-card" aria-label={t.resultContext}>
      <p><Loader2 size={28} className="loading-icon" aria-hidden="true" />{t.checking}</p>
      <button className="secondary-button" type="button" onClick={onCancel}>{t.cancel}</button>
    </section>
  );
  if (state.status === 'error') return (
    <section className="card result-card error-card" aria-labelledby="error-title">
      <h2 id="error-title">{t.errorTitle}</h2>
      <p>{t.errors[state.error.code]}</p>
      {state.submittedText !== null && (
        <button type="button" className="secondary-button" onClick={onRetry}>{t.retry}</button>
      )}
    </section>
  );
  if (state.status !== 'result') return null;
  const result = state.result;
  const limitedText = hasOnlyTextLimitation(state);
  const Icon = { phishing: AlertCircle, suspicious: AlertTriangle, no_clear_signs: SearchCheck, unknown: HelpCircle }[result.assessment];
  return (
    <section className={`result assessment-${result.assessment}`} aria-labelledby="assessment-title">
      <div className="verdict-band">
        <Icon className="verdict-icon" size={60} strokeWidth={2.2} aria-hidden="true" />
        <div>
          <h2 id="assessment-title">{limitedText ? t.limitedTextTitle : t.verdicts[result.assessment]}</h2>
          <p>{limitedText ? t.limitedTextHelp : t.descriptions[result.assessment]}</p>
        </div>
      </div>
      <div className="result-body">
      <div className="reasons-block">
        <h3>{t.reasonsTitle}</h3>
        {result.reasons.length ? reasonList(result.reasons, true) : <p className="muted">{t.noReasons}</p>}
      </div>
      {result.recommended_actions.length > 0 && (
        <div className="action-card">
          <h3>{t.nextStep}</h3>
          <ul className="marked-list">
            {result.recommended_actions.map(action => (
              <li key={action}><Check className="list-icon" size={26} strokeWidth={2.6} aria-hidden="true" /><span>{t.actions[action]}</span></li>
            ))}
          </ul>
        </div>
      )}
      {result.assessment === 'no_clear_signs' && <p className="no-guarantee">{t.noGuarantee}</p>}
      <div className="coverage-block">
        <h3>{t.coverageTitle}</h3>
        <p className="coverage-status">{limitedText ? t.limitedTextTitle : t[result.analysis_status]}</p>
        {result.analysis_status === 'partial' && <p>{t.partialHelp}</p>}
        {result.analysis_status === 'unavailable' && !limitedText && <p>{t.unavailableHelp}</p>}
        {result.limitations.length > 0 && (
          <ul className="evidence-list">
            {result.limitations.map((code, index) => <li key={`${code}-${index}`}>{reasonCopy(code)}</li>)}
          </ul>
        )}
      </div>
      {result.links.length > 0 ? (
        <details className="link-details">
          <summary>{t.linkDetails} ({result.links.length})</summary>
          <p className="muted">{t.maskedHelp}</p>
          <ol className="link-list">
            {result.links.map(link => {
              const normalized = maskedDestination(link.technical?.normalized_url ?? null);
              const final = maskedDestination(link.technical?.final_url ?? null);
              return (
                <li key={link.link_id} className="link-card">
                  <h4>{link.display_host ? <bdi dir="ltr">{link.display_host}</bdi> : t.unknownHost}</h4>
                  <p>{t.linkAssessment}: {t.assessments[link.assessment]}</p>
                  <p className="inspection-status">{t.inspection[link.inspection_status]}</p>
                  {link.reasons.length > 0 && reasonList(link.reasons)}
                  {link.limitations.length > 0 && (
                    <ul className="evidence-list">
                      {link.limitations.map((code, index) => <li key={`${code}-${index}`}>{reasonCopy(code)}</li>)}
                    </ul>
                  )}
                  {(normalized || final) && (
                    <dl className="destinations">
                      {normalized && (
                        <>
                          <dt>{t.normalizedDestination}</dt>
                          <dd><bdi dir="ltr">{normalized}</bdi></dd>
                        </>
                      )}
                      {final && (
                        <>
                          <dt>{t.finalDestination}</dt>
                          <dd><bdi dir="ltr">{final}</bdi></dd>
                        </>
                      )}
                    </dl>
                  )}
                </li>
              );
            })}
          </ol>
        </details>
      ) : <p className="muted no-links">{t.noLinks}</p>}
      </div>
    </section>
  );
}

/** A small, persistent live region announces status without rereading all evidence. */
export function ResultDisplay(props: Props) {
  const { t } = useLanguage();
  const { state } = props;
  const announcement = state.status === 'loading' ? t.checking
    : state.status === 'error' ? t.errorTitle
    : state.status === 'result' ? `${t.resultLabel}: ${hasOnlyTextLimitation(state) ? t.limitedTextTitle : t.verdicts[state.result.assessment]}` : '';
  return (
    <>
      <p className="sr-only" role="status" aria-atomic="true">{announcement}</p>
      <ResultContent {...props} />
    </>
  );
}
