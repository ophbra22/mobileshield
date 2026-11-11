import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ResultDisplay } from './ResultDisplay';
import { LanguageProvider, useLanguage, getTranslations } from '@/app/context/LanguageContext';
import { AnalysisError, parseAnalysisResponse } from '@/lib/analysis';
import type { Assessment, AnalysisErrorCode, Reason } from '@/lib/analysis';
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
  it.each(['en', 'he'] as const)('shows each reason code once per list in %s while preserving independent link evidence', async language => {
    localStorage.setItem('ms_lang', language);
    const s = state('suspicious', 'partial');
    if (s.status !== 'result') throw Error('fixture');
    const first: Reason = { code: 'brand_destination_mismatch', strength: 'medium', source: 'url', link_id: 'link-1', params: { display_host: 'one.example', expected_host: 'paypal.com', brand: 'paypal' } };
    const second: Reason = { ...first, params: { ...first.params, expected_host: 'microsoft.com', brand: 'microsoft' } };
    const third: Reason = { ...first, link_id: 'link-2', params: { ...first.params, display_host: 'two.example' } };
    const urgency: Reason = { code: 'urgency', strength: 'medium', source: 'message', link_id: null, params: {} };
    const lookalike: Reason = { code: 'lookalike_host', strength: 'medium', source: 'url', link_id: 'link-2', params: { display_host: 'two.example', expected_host: 'paypal.com', brand: 'paypal' } };
    s.result.reasons = [first, urgency, second, lookalike, third];
    s.result.links = [
      { ...s.result.links[0], display_host: 'one.example', reasons: [first, urgency, second], limitations: [] },
      { ...s.result.links[0], link_id: 'link-2', display_host: 'two.example', reasons: [third, lookalike, { ...third, source: 'inspection' }], limitations: ['inspection_failed'] },
    ];
    const originalEvidence = JSON.stringify(s.result);
    show(s);
    const t = getTranslations(language);
    const summary = screen.getByRole('heading', { name: t.reasonsTitle }).parentElement!;
    const expectedSummary = [t.reasons.brand_destination_mismatch, t.reasons.urgency, t.reasons.lookalike_host];
    expect(within(summary).getAllByRole('listitem').map(item => item.textContent)).toEqual(expectedSummary);
    await userEvent.setup().click(screen.getByText(`${t.linkDetails} (2)`));
    const firstLink = screen.getByText('one.example').closest('li')!;
    const secondLink = screen.getByText('two.example').closest('li')!;
    expect(within(firstLink).getAllByRole('listitem').map(item => item.textContent)).toEqual(expectedSummary.slice(0, 2));
    expect(within(secondLink).getAllByRole('listitem').map(item => item.textContent)).toEqual([expectedSummary[0], expectedSummary[2], t.reasons.inspection_failed]);
    expect(screen.getAllByText(t.reasons.brand_destination_mismatch)).toHaveLength(3);
    expect(screen.getByText(t.partialHelp)).toBeVisible();
    expect(screen.getByText(t.reasons.inspection_disabled)).toBeVisible();
    expect(JSON.stringify(s.result)).toBe(originalEvidence);
  });
  it('describes observed fields and general certificate verification accurately', () => {
    expect(getTranslations('en').reasons.credential_form).toBe('The linked page contains sign-in or credential fields.');
    expect(getTranslations('en').reasons.payment_form).toBe('The linked page contains payment fields.');
    expect(getTranslations('en').reasons.certificate_mismatch).toBe('The destination certificate could not be verified.');
    expect(getTranslations('he').reasons.certificate_mismatch).toBe('לא ניתן היה לאמת את תעודת האבטחה של היעד.');
  });
  it.each([['phishing', 'This is probably a scam.'], ['suspicious', 'This message has warning signs.'], ['no_clear_signs', 'No clear warning signs found.'], ['unknown', 'We could not assess this message.']] as const)('renders %s without a safe fallback', (assessment, title) => {
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
    expect(screen.getByRole('heading', { name: 'This is probably a scam.' })).toBeVisible();
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
    expect(screen.getByRole('heading', { name: 'יש בהודעה סימני אזהרה.' })).toBeVisible();
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
    const region = screen.getByRole('region', { name: t.verdicts.suspicious });
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

it.each(['en', 'he'] as const)('distinguishes text coverage from unavailable service in %s', language => {
  localStorage.setItem('ms_lang', language);
  const s = state('unknown', 'unavailable');
  if (s.status !== 'result') throw Error('fixture');
  s.result.limitations = ['unsupported_text'];
  s.result.links = [];
  s.result.reasons = [];
  s.result.recommended_actions = [];
  show(s);
  const title = language === 'en' ? 'Limited text coverage' : 'כיסוי טקסט מוגבל';
  expect(screen.getByRole('heading', { name: title })).toBeVisible();
  expect(screen.getByRole('status')).toHaveTextContent(title);
  expect(screen.queryByText(getTranslations(language).unavailable)).not.toBeInTheDocument();
  expect(screen.queryByText(getTranslations(language).unavailableHelp)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: getTranslations(language).retry })).not.toBeInTheDocument();
  expect(document.documentElement.dir).toBe(language === 'he' ? 'rtl' : 'ltr');
});

it.each(['en', 'he'] as const)('shows a completed ordinary message in %s', language => {
  localStorage.setItem('ms_lang', language);
  const s = state('no_clear_signs', 'complete');
  if (s.status !== 'result') throw Error('fixture');
  s.result.limitations = [];
  s.result.links = [];
  s.result.reasons = [];
  s.result.recommended_actions = [];
  show(s);
  const t = getTranslations(language);
  expect(screen.getByRole('heading', { name: t.verdicts.no_clear_signs })).toBeVisible();
  expect(screen.getByText(t.complete)).toBeVisible();
  expect(screen.getByText(t.noGuarantee)).toBeVisible();
  expect(screen.getByText(t.noLinks)).toBeVisible();
});

it.each(['en', 'he'] as const)('preserves unavailable analysis with multiple limitations in %s', language => {
  localStorage.setItem('ms_lang', language);
  const s = state('unknown', 'unavailable');
  if (s.status !== 'result') throw Error('fixture');
  s.result.limitations = ['unsupported_text', 'inspection_failed'];
  show(s);
  const t = getTranslations(language);
  expect(screen.getByRole('heading', { name: t.verdicts.unknown })).toBeVisible();
  expect(screen.getByText(t.unavailable)).toBeVisible();
  expect(screen.getByText(t.unavailableHelp)).toBeVisible();
});

it.each(['en', 'he'] as const)('preserves partial warning and network error copy in %s', language => {
  localStorage.setItem('ms_lang', language);
  const s = state('suspicious', 'partial');
  if (s.status !== 'result') throw Error('fixture');
  s.result.limitations = ['unsupported_text', 'inspection_disabled'];
  const view = render(<LanguageProvider><ResultDisplay state={s} onCancel={vi.fn()} onRetry={vi.fn()} /></LanguageProvider>);
  const t = getTranslations(language);
  expect(screen.getByRole('heading', { name: t.verdicts.suspicious })).toBeVisible();
  expect(screen.getByText(t.partialHelp)).toBeVisible();
  expect(screen.getByText(t.reasons.credential_request)).toBeVisible();
  view.rerender(<LanguageProvider><ResultDisplay state={{ sequenceId: 2, status: 'error', submittedText: 'private', inspectLinks: false, result: null, error: new AnalysisError('network_error') }} onCancel={vi.fn()} onRetry={vi.fn()} /></LanguageProvider>);
  expect(screen.getByRole('heading', { name: t.errorTitle })).toBeVisible();
  expect(screen.getByText(t.errors.network_error)).toBeVisible();
  expect(screen.getByRole('button', { name: t.retry })).toBeVisible();
});
