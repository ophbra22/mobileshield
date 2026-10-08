import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ResultDisplay } from './ResultDisplay';
import { LanguageProvider, useLanguage, getTranslations } from '@/app/context/LanguageContext';
import { AnalysisError, parseAnalysisResponse } from '@/lib/analysis';
import type { Assessment, AnalysisErrorCode } from '@/lib/analysis';
import type { MessageAnalysisState } from '../hooks/useMessageAnalysis';
const codes = [
  'credential_request', 'payment_request', 'urgency', 'brand_destination_mismatch',
  'lookalike_host', 'suspicious_obfuscation', 'credential_form', 'payment_form',
  'local_blocklist_hit', 'certificate_mismatch', 'unsupported_text', 'invalid_link',
  'inspection_disabled', 'inspection_failed', 'destination_blocked', 'body_limit',
  'deadline_exceeded', 'unknown_reason',
];

function state(assessment: Assessment = 'suspicious', analysis_status = 'complete'): MessageAnalysisState {
  return {
    sequenceId: 1,
    status: 'result',
    submittedText: 'secret message',
    inspectLinks: false,
    error: null,
    result: parseAnalysisResponse({
      schema_version: 1,
      assessment,
      analysis_status,
      reasons: [{ code: 'credential_request', source: 'message', strength: 'strong', link_id: null, params: {} }],
      recommended_actions: ['do_not_share_secrets'],
      limitations: ['inspection_disabled'],
      request_id: 'test',
      links: [{
        link_id: 'link-1',
        assessment: 'unknown',
        inspection_status: 'not_requested',
        display_host: 'example.com',
        reasons: [],
        limitations: ['inspection_disabled'],
        technical: {
          normalized_url: 'https://username:password@example.com/private?token=SECRET#code',
          final_url: null,
        },
      }],
    }),
  };
}

function Switch() {
  const { toggleLanguage } = useLanguage();
  return <button onClick={toggleLanguage}>Language</button>;
}

function show(s: MessageAnalysisState) {
  render(
    <LanguageProvider>
      <Switch />
      <ResultDisplay state={s} onCancel={vi.fn()} onRetry={vi.fn()} />
    </LanguageProvider>
  );
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem('ms_lang', 'en');
});

describe('validated evidence presentation', () => {
  it('describes observed fields and general certificate verification accurately', () => {
    expect(getTranslations('en').reasons.credential_form).toBe('The linked page contains sign-in or credential fields.');
    expect(getTranslations('en').reasons.payment_form).toBe('The linked page contains payment fields.');
    expect(getTranslations('en').reasons.certificate_mismatch).toBe('The destination certificate could not be verified.');
    expect(getTranslations('he').reasons.certificate_mismatch).toBe('לא ניתן היה לאמת את תעודת האבטחה של היעד.');
  });
  it.each([['phishing', 'Phishing warning'], ['suspicious', 'Suspicious signs'], ['no_clear_signs', 'No clear warning signs'], ['unknown', 'Unable to assess']] as const)('renders %s without a safe fallback', (assessment, title) => {
    show(state(assessment));
    expect(screen.getByRole('heading', { name: title })).toBeVisible();
    expect(screen.queryByText(/Safe Link|benign|confidence|\d+%/i)).not.toBeInTheDocument();
    expect(screen.getByText('Do not share passwords, payment details or one-time codes.')).toBeVisible();
  });
  it('explains no-clear-signs without changing a complete static summary', () => {
    show(state('no_clear_signs'));
    expect(screen.getByText('This is not a safety guarantee. New or subtle threats may go undetected.')).toBeVisible();
    expect(screen.getByText('Requested checks completed')).toBeVisible();
    expect(screen.getAllByText('Linked pages were not visited.')).toHaveLength(2);
    expect(screen.queryByText('Analysis incomplete')).not.toBeInTheDocument();
  });
  it.each(['partial', 'unavailable'])('separates %s coverage from warning assessment', (coverage) => {
    show(state('phishing', coverage));
    expect(screen.getByRole('heading', { name: 'Phishing warning' })).toBeVisible();
    expect(screen.getByText(coverage === 'partial' ? 'Analysis incomplete' : 'Analysis unavailable')).toBeVisible();
  });
  it('isolates nonclickable domains and masks all private URL parts even in expanded evidence', async () => {
    show(state());
    const domain = screen.getByText('example.com');
    expect(domain.tagName).toBe('BDI');
    expect(domain).toHaveAttribute('dir', 'ltr');
    expect(domain.closest('a')).toBeNull();
    const details = screen.getByText('Link details (1)').closest('details')!;
    expect(details).not.toHaveAttribute('open');
    const user = userEvent.setup();
    await user.tab();
    await user.tab();
    expect(screen.getByText('Link details (1)')).toHaveFocus();
    expect(screen.getByText('Link details (1)').tagName).toBe('SUMMARY');
    // jsdom does not implement native summary Enter/Space activation; Task7 verifies it in a browser.
    await user.click(screen.getByText('Link details (1)'));
    expect(details).toHaveAttribute('open');
    expect(document.body.textContent).not.toMatch(/username|password@|private\?|SECRET|secret message/);
    expect(screen.getByText('https://example.com/…')).toHaveAttribute('dir', 'ltr');
    expect(within(details).getByText('Page not visited')).toBeInTheDocument();
  });
  it('localizes warnings, actions and limitations when language changes', () => {
    show(state());
    expect(screen.getByText('The message asks for passwords or one-time codes.')).toBeVisible();
    fireEvent.click(screen.getByText('Language'));
    expect(screen.getByRole('heading', { name: 'סימנים חשודים' })).toBeVisible();
    expect(screen.getByText('ההודעה מבקשת סיסמאות או קודים חד־פעמיים.')).toBeVisible();
    expect(screen.getByText('אל תשתפו סיסמאות, פרטי תשלום או קודים חד־פעמיים.')).toBeVisible();
  });
  it.each(['en', 'he'] as const)('renders all warning reasons and actions in %s', language => {
    localStorage.setItem('ms_lang', language);
    const s = state();
    if (s.status !== 'result')
      throw Error('fixture');
    s.result.reasons = codes.map(code => ({ code, strength: 'info', source: 'message', link_id: null, params: {} }));
    s.result.recommended_actions = ['avoid_interaction', 'verify_independently', 'do_not_share_secrets', 'consider_link_inspection', 'retry_later'];
    show(s);
    const t = getTranslations(language);
    const region = screen.getByRole('region', { name: t.assessments.suspicious });
    for (const code of codes)
      expect(within(region).getAllByText(t.reasons[code as keyof typeof t.reasons])[0]).toBeVisible();
    for (const action of s.result.recommended_actions)
      expect(within(region).getByText(t.actions[action])).toBeVisible();
  });
  it('provides every reason, action and inspection status in Hebrew and English', () => {
    for (const language of ['en', 'he'] as const) {
      const t = getTranslations(language);
      for (const code of codes)
        expect(t.reasons[code as keyof typeof t.reasons]).toBeTruthy();
      for (const code of ['avoid_interaction', 'verify_independently', 'do_not_share_secrets', 'consider_link_inspection', 'retry_later'] as const)
        expect(t.actions[code]).toBeTruthy();
      for (const code of ['not_requested', 'completed', 'blocked', 'failed', 'skipped'] as const)
        expect(t.inspection[code]).toBeTruthy();
    }
  });
  it.each(['invalid_request', 'invalid_response', 'analysis_unavailable', 'rate_limit_exceeded', 'request_failed', 'network_error', 'timeout', 'cancelled'] as AnalysisErrorCode[])('shows bounded %s error with no safe copy', (code) => {
    show({ sequenceId: 1, status: 'error', submittedText: 'secret message', inspectLinks: false, result: null, error: new AnalysisError(code) });
    expect(screen.getByRole('heading', { name: 'Check could not finish' })).toBeVisible();
    expect(screen.getByText(getTranslations('en').errors[code])).toBeVisible();
    expect(screen.queryByText(/Safe Link|No clear warning signs/)).not.toBeInTheDocument();
  });
  it('announces pending status once and never renders a previous assessment', () => {
    show({ sequenceId: 1, status: 'loading', submittedText: 'secret message', inspectLinks: false, result: null, error: null });
    expect(screen.getAllByRole('status')).toHaveLength(1);
    expect(screen.getByRole('status')).toHaveTextContent('Checking message…');
    expect(screen.queryByText(/Safe Link|No clear warning signs/)).not.toBeInTheDocument();
  });
  it('uses a generic translated limitation for unknown reason codes', () => {
    const s = state();
    if (s.status !== 'result')
      throw Error('fixture');
    s.result.reasons[0].code = 'future_code';
    show(s);
    expect(screen.getByText('Some evidence could not be interpreted.')).toBeVisible();
    expect(screen.queryByText('future_code')).not.toBeInTheDocument();
  });
});
