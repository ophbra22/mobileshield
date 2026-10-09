import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Home from '../page';
import { LanguageProvider } from '../context/LanguageContext';
import { POST } from '../api/report/pdf/route';

const result = { schema_version: 1, assessment: 'suspicious', analysis_status: 'complete',
  reasons: [{ code: 'urgency', strength: 'medium', source: 'message', link_id: null, params: {} }],
  recommended_actions: ['verify_independently'], limitations: [], links: [], request_id: 'test-request' };
function show() { render(<LanguageProvider><Home /></LanguageProvider>); }
function deferred() { let resolve!: (r: Response) => void; const promise = new Promise<Response>(r => { resolve = r; }); return {promise,resolve}; }
const response = () => new Response(JSON.stringify(result), {status:200,headers:{'Content-Type':'application/json'}});
beforeEach(() => { localStorage.clear(); localStorage.setItem('ms_lang','en'); vi.stubGlobal('fetch',vi.fn().mockResolvedValue(response())); });

describe('message form with the real request lifecycle', () => {
  it('has a visible message label, language direction and explicit unchecked inspection', () => {
    show(); const input = screen.getByRole('textbox',{name:'Message to check'});
    expect(screen.getByText('Message to check')).toBeVisible(); expect(input).toHaveAttribute('dir','ltr');
    expect(screen.getByRole('checkbox',{name:'Inspect linked pages too'})).not.toBeChecked();
    expect(screen.queryByText(/AI|confidence|Safe Link/)).not.toBeInTheDocument();
  });
  it.each(['en', 'he'] as const)('uses %s direction for an empty draft and follows language changes', language => {
    localStorage.setItem('ms_lang', language); show();
    const input = screen.getByRole('textbox');
    expect(input).toHaveValue('');
    expect(input).toHaveAttribute('dir', language === 'he' ? 'rtl' : 'ltr');
    fireEvent.click(screen.getByRole('button', { name: language === 'he' ? 'מעבר לאנגלית' : 'Switch to Hebrew' }));
    expect(input).toHaveValue('');
    expect(input).toHaveAttribute('dir', language === 'he' ? 'ltr' : 'rtl');
  });
  it.each(['en', 'he'] as const)('uses %s direction for whitespace and updates it after a language change', language => {
    localStorage.setItem('ms_lang', language); show();
    const input = screen.getByRole('textbox');
    const whitespace = ' \t\n ';
    fireEvent.change(input, { target: { value: whitespace } });
    expect(input).toHaveValue(whitespace);
    expect(input).toHaveAttribute('dir', language === 'he' ? 'rtl' : 'ltr');
    fireEvent.click(screen.getByRole('button', { name: language === 'he' ? 'מעבר לאנגלית' : 'Switch to Hebrew' }));
    expect(input).toHaveValue(whitespace);
    expect(input).toHaveAttribute('dir', language === 'he' ? 'ltr' : 'rtl');
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([
    ['en', 'שלום hello https://example.com'], ['he', 'שלום hello https://example.com'],
    ['en', 'Hello שלום https://example.com'], ['he', 'Hello שלום https://example.com'],
  ] as const)('keeps automatic text direction in %s for %s through language changes and restores empty direction', (language, text) => {
    localStorage.setItem('ms_lang', language); show();
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: text } });
    expect(input).toHaveAttribute('dir', 'auto');
    fireEvent.click(screen.getByRole('button', { name: language === 'he' ? 'מעבר לאנגלית' : 'Switch to Hebrew' }));
    expect(input).toHaveValue(text);
    expect(input).toHaveAttribute('dir', 'auto');
    fireEvent.click(screen.getByRole('button', { name: language === 'he' ? 'Clear' : 'ניקוי' }));
    expect(input).toHaveValue('');
    expect(input).toHaveAttribute('dir', language === 'he' ? 'ltr' : 'rtl');
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each(['en', 'he'])('explains server-visit tracking and one-time-link consequences in %s', (language) => {
    localStorage.setItem('ms_lang', language); show();
    const checkbox = screen.getByRole('checkbox');
    const help = document.getElementById(checkbox.getAttribute('aria-describedby')!);
    expect(help).toBeVisible();
    expect(checkbox).not.toBeChecked();
    if (language === 'en') {
      expect(help).toHaveTextContent(/server visits/);
      expect(help).toHaveTextContent(/activate tracking or a one-time link/);
    } else {
      expect(help).toHaveTextContent(/השרת מבקר/);
      expect(help).toHaveTextContent(/להפעיל מעקב או קישור חד־פעמי/);
    }
  });
  it('reads clipboard only on request and preserves manual text on denial', async () => {
    const readText = vi.fn().mockRejectedValue(new Error('denied SECRET'));
    Object.defineProperty(navigator,'clipboard',{value:{readText},configurable:true});
    show(); expect(readText).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'manual message'}});
    fireEvent.click(screen.getByRole('button',{name:'Paste'}));
    expect(await screen.findByText('Clipboard unavailable. Paste or type your message manually.')).toBeVisible();
    expect(screen.getByRole('textbox')).toHaveValue('manual message');
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'updated manually'}});
    fireEvent.click(screen.getByRole('button',{name:'Check message'}));
    await screen.findByRole('heading',{name:'Suspicious signs'});
    expect(JSON.parse(vi.mocked(fetch).mock.calls[0][1]!.body as string)).toEqual({text:'updated manually',inspect_links:false});
    expect(screen.queryByText(/SECRET/)).not.toBeInTheDocument();
  });
  it('submits every link as full unmodified message and counts Unicode code points', async () => {
    show(); const text = '🙂e\u0301 hello https://one.example/?token=private https://two.example';
    fireEvent.change(screen.getByRole('textbox'),{target:{value:text}});
    expect(document.getElementById('message-count')).toHaveTextContent(`${Array.from(text).length} / 10,000 characters`);
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button',{name:'Check message'}));
    await screen.findByRole('heading',{name:'Suspicious signs'});
    expect(JSON.parse(vi.mocked(fetch).mock.calls[0][1]!.body as string)).toEqual({text,inspect_links:true});
    expect(within(screen.getByRole('region', {name:'Suspicious signs'})).queryByText(text)).not.toBeInTheDocument(); // No secret-bearing message echo in evidence.
  });
  it('rejects over-limit text without truncation', () => {
    show(); const text = '🙂'.repeat(10001); fireEvent.change(screen.getByRole('textbox'),{target:{value:text}});
    expect(screen.getByRole('textbox')).toHaveValue(text);
    expect(screen.getByText('The message exceeds 10,000 characters. Shorten it before checking.')).toBeVisible();
    expect(screen.getByRole('button',{name:'Check message'})).toBeDisabled();
  });
  it('keeps pending snapshot through a language change and updates page direction', async () => {
    const pending=deferred(); vi.mocked(fetch).mockReturnValue(pending.promise); show();
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'original message'}});
    fireEvent.click(screen.getByRole('button',{name:'Check message'}));
    expect(screen.getByRole('status')).toHaveTextContent('Checking message…');
    fireEvent.click(screen.getByRole('button',{name:'Switch to Hebrew'}));
    expect(document.documentElement).toHaveAttribute('lang','he'); expect(document.documentElement).toHaveAttribute('dir','rtl');
    expect(screen.getByRole('textbox')).toHaveValue('original message');
    expect(screen.getByRole('status')).toHaveTextContent('בודקים את ההודעה…');
    await act(async()=>pending.resolve(response()));
    await screen.findByRole('heading',{name:'סימנים חשודים'}); expect(fetch).toHaveBeenCalledTimes(1);
  });
  it.each(['edit','inspection','clear','cancel'])('invalidates pending results on %s',async(change)=>{
    const pending=deferred(); vi.mocked(fetch).mockReturnValue(pending.promise); show();
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'original'}});
    fireEvent.click(screen.getByRole('button',{name:'Check message'}));
    if(change==='edit') fireEvent.change(screen.getByRole('textbox'),{target:{value:'new draft'}});
    if(change==='inspection') fireEvent.click(screen.getByRole('checkbox'));
    if(change==='clear') fireEvent.click(screen.getByRole('button',{name:'Clear'}));
    if(change==='cancel') fireEvent.click(screen.getByRole('button',{name:'Cancel check'}));
    await act(async()=>pending.resolve(response()));
    expect(screen.queryByRole('heading',{name:'Suspicious signs'})).not.toBeInTheDocument();
    expect(screen.queryByText('Checking message…')).not.toBeInTheDocument();
    expect(screen.getByRole('textbox')).toHaveValue(change==='clear'?'':change==='edit'?'new draft':'original');
  });
  it('clears completed evidence with the draft',async()=>{
    show(); fireEvent.change(screen.getByRole('textbox'),{target:{value:'test'}});
    fireEvent.click(screen.getByRole('button',{name:'Check message'})); await screen.findByRole('heading',{name:'Suspicious signs'});
    fireEvent.click(screen.getByRole('button',{name:'Clear'}));
    expect(screen.getByRole('textbox')).toHaveValue(''); expect(screen.queryByRole('heading',{name:'Suspicious signs'})).not.toBeInTheDocument();
  });
  it('retries the failed snapshot explicitly and clears retry on an edit',async()=>{
    vi.mocked(fetch).mockResolvedValueOnce(new Response('{}',{status:503})).mockResolvedValueOnce(response()); show();
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'failed snapshot'}});
    fireEvent.click(screen.getByRole('button',{name:'Check message'})); await screen.findByRole('button',{name:'Retry check'});
    fireEvent.click(screen.getByRole('button',{name:'Retry check'})); await screen.findByRole('heading',{name:'Suspicious signs'});
    expect(JSON.parse(vi.mocked(fetch).mock.calls[1][1]!.body as string)).toEqual({text:'failed snapshot',inspect_links:false});
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'edited'}});
    expect(screen.queryByRole('button',{name:'Retry check'})).not.toBeInTheDocument();
  });
  it('removes retry eligibility when editing an error snapshot',async()=>{
    vi.mocked(fetch).mockResolvedValue(new Response('{}',{status:503})); show();
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'failed snapshot'}});
    fireEvent.click(screen.getByRole('button',{name:'Check message'})); await screen.findByRole('button',{name:'Retry check'});
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'new draft'}});
    expect(screen.queryByRole('button',{name:'Retry check'})).not.toBeInTheDocument();
    expect(screen.queryByRole('heading',{name:'Check could not finish'})).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it.each(['edit','clear'])('does not restore a stale clipboard read after %s',async(change)=>{
    let resolve!: (text:string)=>void; const pending=new Promise<string>(r=>{resolve=r;});
    Object.defineProperty(navigator,'clipboard',{value:{readText:()=>pending},configurable:true}); show();
    fireEvent.click(screen.getByRole('button',{name:'Paste'}));
    if(change==='edit') fireEvent.change(screen.getByRole('textbox'),{target:{value:'manual'}});
    else fireEvent.click(screen.getByRole('button',{name:'Clear'}));
    await act(async()=>resolve('stale clipboard'));
    expect(screen.getByRole('textbox')).toHaveValue(change==='edit'?'manual':'');
  });
  it('offers keyboard accessible language and contact/social footer affordances',async()=>{
    const user=userEvent.setup(); show(); await user.tab();
    expect(screen.getByRole('button',{name:'Switch to Hebrew'})).toHaveFocus();
    expect(screen.getByRole('link',{name:'Contact us'})).toHaveAttribute('href','mailto:MobileShield@gmail.com');
    expect(screen.getByRole('link',{name:'LinkedIn'})).toHaveAttribute('rel','noopener noreferrer');
  });
});

it('retires the PDF endpoint with no-store 410 without reading the request',async()=>{
  const request = new Request('http://localhost/api/report/pdf',{method:'POST',body:'not json'});
  const r = await POST(request as never); expect(r.status).toBe(410); expect(r.headers.get('Cache-Control')).toBe('no-store');
});
