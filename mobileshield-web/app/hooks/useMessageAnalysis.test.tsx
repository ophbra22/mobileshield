import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { LanguageProvider, useLanguage } from '../context/LanguageContext';
import { useMessageAnalysis } from './useMessageAnalysis';

const response = (assessment = 'suspicious') => new Response(JSON.stringify({
  schema_version:1,assessment,analysis_status:'complete',reasons:[],recommended_actions:['verify_independently'],limitations:[],links:[],request_id:'c7f7fe4fd9064f72951a7ce9a7677d30',
}),{headers:{'Content-Type':'application/json'}});
function deferred<T>() {
  let resolve!: (value:T) => void;
  let reject!: (error:unknown) => void;
  const promise=new Promise<T>((res,rej) => {resolve=res;reject=rej;});
  return {promise,resolve,reject};
}

describe('message request lifecycle', () => {
  it('retains an immutable submitted snapshot rather than the mutable input object', async () => {
    const pending=deferred<Response>(); vi.stubGlobal('fetch',vi.fn(() => pending.promise));
    const {result}=renderHook(() => useMessageAnalysis());
    const input={text:'full original message 😀',inspect_links:true};
    act(() => { void result.current.submit(input); });
    input.text='edited'; input.inspect_links=false;
    expect(result.current.state).toMatchObject({status:'loading',submittedText:'full original message 😀',inspectLinks:true,sequenceId:1});
    pending.resolve(response());
    await waitFor(() => expect(result.current.state.status).toBe('result'));
    expect(result.current.state.submittedText).toBe('full original message 😀');
  });
  it('allows only the newest response to set a result', async () => {
    const old=deferred<Response>(),current=deferred<Response>();
    const signals:AbortSignal[]=[];
    vi.stubGlobal('fetch',vi.fn((_url,init) => {signals.push(init.signal);return signals.length===1?old.promise:current.promise;}));
    const {result}=renderHook(() => useMessageAnalysis());
    act(() => { void result.current.submit({text:'old message',inspect_links:false}); });
    act(() => { void result.current.submit({text:'new message',inspect_links:true}); });
    expect(signals[0].aborted).toBe(true);
    current.resolve(response('phishing'));
    await waitFor(() => expect(result.current.state.status).toBe('result'));
    old.resolve(response('no_clear_signs'));
    await act(async () => {await old.promise;});
    expect(result.current.state).toMatchObject({status:'result',sequenceId:2,submittedText:'new message',result:{assessment:'phishing'}});
  });
  it.each(['cancel','invalidate'] as const)('%s prevents a late response from restoring cleared state', async action => {
    const pending=deferred<Response>(); vi.stubGlobal('fetch',vi.fn(() => pending.promise));
    const {result}=renderHook(() => useMessageAnalysis());
    act(() => { void result.current.submit({text:'message to clear',inspect_links:false}); });
    act(() => { result.current[action](); });
    expect(result.current.state).toMatchObject({status:'idle',submittedText:null,result:null,error:null});
    pending.resolve(response()); await act(async () => {await pending.promise;});
    expect(result.current.state.status).toBe('idle');
    act(() => { void result.current.retry(); });
    expect(result.current.state.status).toBe('idle');
  });
  it('invalidates a completed result when content or inspection choice changes', async () => {
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue(response()));
    const {result}=renderHook(() => useMessageAnalysis());
    await act(async () => {await result.current.submit({text:'original',inspect_links:false});});
    expect(result.current.state.status).toBe('result');
    act(() => {result.current.invalidate();});
    expect(result.current.state).toMatchObject({status:'idle',submittedText:null,result:null});
  });
  it('changes language while preserving content and the current request', async () => {
    const pending=deferred<Response>(); vi.stubGlobal('fetch',vi.fn(() => pending.promise));
    const {result}=renderHook(() => ({analysis:useMessageAnalysis(),language:useLanguage()}),{wrapper:LanguageProvider});
    act(() => { void result.current.analysis.submit({text:'שלח את הקוד',inspect_links:false}); });
    act(() => {result.current.language.setLanguage('en');});
    expect(result.current.analysis.state).toMatchObject({status:'loading',submittedText:'שלח את הקוד',sequenceId:1});
    pending.resolve(response('phishing'));
    await waitFor(() => expect(result.current.analysis.state.status).toBe('result'));
    expect(result.current.analysis.state.submittedText).toBe('שלח את הקוד');
    expect(result.current.language.lang).toBe('en');
  });
  it('does not auto-retry errors and retries the submitted snapshot only on a user action', async () => {
    const fetcher=vi.fn().mockResolvedValueOnce(new Response('server-secret',{status:503})).mockResolvedValueOnce(response('unknown'));
    vi.stubGlobal('fetch',fetcher);
    const {result}=renderHook(() => useMessageAnalysis());
    await act(async () => {await result.current.submit({text:'same original text',inspect_links:true});});
    expect(result.current.state).toMatchObject({status:'error',submittedText:'same original text',error:{code:'analysis_unavailable'}});
    expect(fetcher).toHaveBeenCalledTimes(1);
    await act(async () => {await result.current.retry();});
    expect(result.current.state).toMatchObject({status:'result',sequenceId:2,submittedText:'same original text',inspectLinks:true});
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({text:'same original text',inspect_links:true});
  });
  it('cancels the in-flight retry without letting either attempt restore a result', async () => {
    const retry=deferred<Response>();
    vi.stubGlobal('fetch',vi.fn().mockResolvedValueOnce(new Response('secret',{status:429})).mockReturnValueOnce(retry.promise));
    const {result}=renderHook(() => useMessageAnalysis());
    await act(async () => {await result.current.submit({text:'original text',inspect_links:false});});
    act(() => {void result.current.retry();});
    act(() => {result.current.cancel();});
    retry.resolve(response()); await act(async () => {await retry.promise;});
    expect(result.current.state.status).toBe('idle');
  });
  it('aborts on unmount and does not persist the submitted message or result', async () => {
    let transportSignal:AbortSignal|undefined;
    const fetcher=vi.fn((_url,init) => {transportSignal=init.signal;return new Promise(() => {});});
    vi.stubGlobal('fetch',fetcher);
    const {result,unmount}=renderHook(() => useMessageAnalysis());
    act(() => {void result.current.submit({text:'private message',inspect_links:true});});
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
    unmount();
    expect(transportSignal?.aborted).toBe(true);
  });
  it('times out with a bounded error and retains the submitted snapshot for explicit retry', async () => {
    vi.useFakeTimers(); vi.stubGlobal('fetch',vi.fn(() => new Promise(() => {})));
    const {result}=renderHook(() => useMessageAnalysis());
    act(() => {void result.current.submit({text:'original text',inspect_links:true});});
    await act(async () => {await vi.advanceTimersByTimeAsync(30000);});
    expect(result.current.state).toMatchObject({status:'error',submittedText:'original text',error:{code:'timeout'}});
  });
});
