import { describe, expect, it, vi } from 'vitest';
import { CLIENT_REQUEST_TIMEOUT_MS, normalizeLegacyVerdict, parseAnalysisResponse, validateMessageRequest } from './analysis';
import { analyzeMessage } from './api';

const response = () => ({
  schema_version: 1,
  assessment: 'no_clear_signs',
  analysis_status: 'complete',
  reasons: [],
  recommended_actions: ['verify_independently'],
  limitations: ['inspection_disabled'],
  links: [{
    link_id: 'link_1', assessment: 'unknown', inspection_status: 'not_requested',
    display_host: 'example.com', reasons: [], limitations: ['inspection_disabled'],
    technical: { normalized_url: 'https://example.com/private?token=secret', final_url: null },
  }],
  request_id: 'c7f7fe4fd9064f72951a7ce9a7677d30',
});
const signal = () => new AbortController().signal;

describe('legacy verdicts', () => {
  it.each([
    ['phishing', 'partial', 'phishing'], ['malicious', 'partial', 'phishing'],
    ['unknown', 'complete', 'unknown'], ['unknown', 'unavailable', 'unknown'],
    ['suspicious', 'partial', 'suspicious'], ['no_clear_signs', 'complete', 'no_clear_signs'],
    ['legitimate', 'complete', 'no_clear_signs'], ['safe', 'complete', 'no_clear_signs'],
    ['legitimate', 'partial', 'unknown'], ['safe', 'unavailable', 'unknown'],
    ['no_clear_signs', 'partial', 'unknown'],
  ] as const)('normalizes %s with %s coverage', (value, status, expected) => {
    expect(normalizeLegacyVerdict(value, status)).toBe(expected);
  });
  it.each(['alien', undefined, null, 95, 'BENIGN'])('rejects unrecognized verdict %s', value => {
    expect(() => normalizeLegacyVerdict(value, 'complete')).toThrow();
  });
});

describe('message contract', () => {
  it('preserves static summary coverage without converting optional unvisited links to uncertainty', () => {
    const parsed = parseAnalysisResponse(response());
    expect(parsed.assessment).toBe('no_clear_signs');
    expect(parsed.analysis_status).toBe('complete');
    expect(parsed.links[0].assessment).toBe('unknown');
    expect(parsed.limitations).toEqual(['inspection_disabled']);
    expect(parsed).not.toHaveProperty('confidence');
    expect(parsed).not.toHaveProperty('risk_score');
  });
  it.each([
    null, 'not json', [], {},
    { ...response(), schema_version: 2 },
    { ...response(), schema_version: '1' },
    { ...response(), assessment: 'safe' },
    { ...response(), analysis_status: 'done' },
    { ...response(), recommended_actions: ['alien'] },
    { ...response(), request_id: 'x'.repeat(129) },
    { ...response(), risk_score: 90, confidence: 'high' },
    { ...response(), links: Array.from({length: 11}, (_, i) => ({...response().links[0], link_id: `link_${i}`})) },
    { ...response(), reasons: Array.from({length: 33}, () => ({code:'urgency',strength:'medium',source:'message',link_id:null,params:{}})) },
    { ...response(), reasons: [{code:'urgency',strength:'medium',source:'message',link_id:null,params:{excerpt:'token-secret'}}] },
    { ...response(), reasons: [{code:'urgency',strength:'high',source:'message',link_id:null,params:{}}] },
    { ...response(), reasons: [{code:'lookalike_host',strength:'strong',source:'url',link_id:'link_1',params:{display_host:'example.com?token=secret'}}] },
    { ...response(), reasons: [{code:'lookalike_host',strength:'strong',source:'url',link_id:'link_1',params:{brand:'arbitrary secret'}}] },
    { ...response(), links: [{...response().links[0], inspection_status:'visited'}] },
    { ...response(), links: [{...response().links[0], technical:{ normalized_url:17 }}] },
    { ...response(), links: [response().links[0], response().links[0]] },
    { ...response(), reasons: [{code:'urgency',strength:'medium',source:'message',link_id:'absent',params:{}}] },
  ])('rejects malformed or unbounded envelope %#', value => {
    expect(() => parseAnalysisResponse(value)).toThrow();
  });
  it('validates safe known reason facts and handles unknown codes as generic limitations', () => {
    const parsed = parseAnalysisResponse({ ...response(),
      reasons: [{code:'lookalike_host',strength:'strong',source:'url',link_id:'link_1',params:{display_host:'example.com',expected_host:'paypal.com',brand:'paypal'}},
        {code:'future_code',strength:'info',source:'inspection',link_id:null,params:{}}],
      limitations:['future_limit'],
    });
    expect(parsed.reasons[0].params).toEqual({display_host:'example.com',expected_host:'paypal.com',brand:'paypal'});
    expect(parsed.reasons[1].code).toBe('unknown_reason');
    expect(parsed.limitations).toEqual(['unknown_reason']);
  });
  it.each([
    ['😀'.repeat(10000), 10000], ['e\u0301'.repeat(5000), 10000],
    ['א😀e\u0301', 4],
    ['\ufeff', 1],
  ])('counts code points and preserves full text %#', (text, length) => {
    expect(Array.from(text).length).toBe(length);
    expect(validateMessageRequest({text, inspect_links:false}).text).toBe(text);
  });
  it.each([
    {text:'😀'.repeat(10001),inspect_links:false},
    {text:'e\u0301'.repeat(5001),inspect_links:false},
    {text:' \n\t',inspect_links:false},
    {text:'\u0085\u001c',inspect_links:false},
    {text:'hello',inspect_links:'false'},
    {text:'hello',inspect_links:false,url:'https://example.com'},
  ])('rejects invalid request without truncation %#', value => {
    expect(() => validateMessageRequest(value)).toThrow();
  });
});

describe('public message transport', () => {
  it('sends the full message and explicit inspection flag without saved credentials, cookies or cache', async () => {
    localStorage.setItem('jwt', 'saved-secret');
    localStorage.setItem('manual_api_key', 'saved-key');
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(response()), {headers:{'Content-Type':'application/json'}}));
    vi.stubGlobal('fetch', fetcher);
    const text = 'Send your OTP at https://example.com or https://second.example';
    const result = await analyzeMessage({text,inspect_links:false}, signal());
    expect(result.assessment).toBe('no_clear_signs');
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toBe('http://localhost:8000/v1/analyze-message');
    expect(JSON.parse(init.body)).toEqual({text,inspect_links:false});
    expect(new Headers(init.headers).get('authorization')).toBeNull();
    expect(new Headers(init.headers).get('x-api-key')).toBeNull();
    expect(init.credentials).toBe('omit');
    expect(init.cache).toBe('no-store');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(localStorage.getItem('jwt')).toBe('saved-secret');
    expect(localStorage.length).toBe(2);
  });
  it.each([
    [503, 'application/json', '{"detail":"secret-token","request_id":"secret-token"}', 'analysis_unavailable'],
    [429, 'text/html', '<p>secret-token</p>', 'rate_limit_exceeded'],
    [422, 'application/json', '{"detail":[{"input":"secret-token"}]}', 'invalid_request'],
    [413, 'application/json', '{"detail":"secret-token"}', 'invalid_request'],
    [500, 'text/html', '<p>secret-token</p>', 'request_failed'],
    [200, 'text/html', '<p>secret-token</p>', 'invalid_response'],
    [200, 'application/json', '{"secret-token":', 'invalid_response'],
    [200, 'application/json', '{"risk_score":99}', 'invalid_response'],
  ])('maps status %s to bounded localized error code %#', async (status, contentType, body, code) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body,{status,headers:{'Content-Type':contentType}})));
    await expect(analyzeMessage({text:'hello',inspect_links:false},signal())).rejects.toMatchObject({code,message:code});
  });
  it('redacts transport exception messages', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('token=secret')));
    await expect(analyzeMessage({text:'hello',inspect_links:false},signal())).rejects.toMatchObject({code:'network_error',message:'network_error'});
  });
  it('enforces the client deadline and aborts the network request', async () => {
    vi.useFakeTimers();
    let transportSignal: AbortSignal | undefined;
    vi.stubGlobal('fetch', vi.fn((_url,init) => { transportSignal=init.signal; return new Promise(() => {}); }));
    const request = analyzeMessage({text:'hello',inspect_links:true},signal());
    const assertion = expect(request).rejects.toMatchObject({code:'timeout'});
    await vi.advanceTimersByTimeAsync(CLIENT_REQUEST_TIMEOUT_MS);
    await assertion;
    expect(transportSignal?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
  it('honors cancellation even when the transport ignores the abort signal', async () => {
    const controller = new AbortController();
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
    const request = analyzeMessage({text:'hello',inspect_links:false},controller.signal);
    controller.abort();
    await expect(request).rejects.toMatchObject({code:'cancelled'});
  });
  it('never starts a request with invalid text or an already-aborted signal', async () => {
    const fetcher=vi.fn();
    vi.stubGlobal('fetch',fetcher);
    await expect(analyzeMessage({text:' ',inspect_links:false},signal())).rejects.toMatchObject({code:'invalid_request'});
    const controller=new AbortController(); controller.abort();
    await expect(analyzeMessage({text:'hello',inspect_links:false},controller.signal)).rejects.toMatchObject({code:'cancelled'});
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe('reason codes added with the scam-scenario rules', () => {
  it('keeps the new codes and their host facts instead of degrading them to unknown_reason', () => {
    const parsed = parseAnalysisResponse({
      ...response(), assessment: 'suspicious',
      reasons: [
        {code:'shortened_link',strength:'medium',source:'url',link_id:'link_1',params:{display_host:'bit.ly'}},
        {code:'high_abuse_domain_ending',strength:'medium',source:'url',link_id:'link_1',params:{display_host:'example.top'}},
        {code:'scam_scenario',strength:'medium',source:'message',link_id:null,params:{}},
        {code:'brand_destination_mismatch',strength:'strong',source:'message',link_id:'link_1',params:{brand:'isracard'}},
      ],
    });
    expect(parsed.reasons.map(reason => reason.code)).toEqual(['shortened_link', 'high_abuse_domain_ending', 'scam_scenario', 'brand_destination_mismatch']);
    expect(parsed.reasons[0].params).toEqual({display_host:'bit.ly'});
  });
});
