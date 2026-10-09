'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { analyzeMessage } from '@/lib/api';
import { AnalysisError, validateMessageRequest } from '@/lib/analysis';
import type { MessageRequest, MessageResponse } from '@/lib/analysis';

interface RequestSnapshot {
  readonly sequenceId: number;
  readonly submittedText: string | null;
  readonly inspectLinks: boolean | null;
}
export type MessageAnalysisState = RequestSnapshot & (
  | { readonly status: 'idle' | 'loading'; readonly result: null; readonly error: null }
  | { readonly status: 'result'; readonly result: MessageResponse; readonly error: null }
  | { readonly status: 'error'; readonly result: null; readonly error: AnalysisError }
);
export interface MessageAnalysis {
  state: MessageAnalysisState;
  submit: (input: MessageRequest) => Promise<void>;
  cancel: () => void;
  invalidate: () => void;
  retry: () => Promise<void>;
}
const idle = (sequenceId: number): MessageAnalysisState => ({
  sequenceId, submittedText: null, inspectLinks: null, status: 'idle', result: null, error: null,
});

/** Call invalidate on edits/clear/inspection changes. Language is presentation only. */
export function useMessageAnalysis(): MessageAnalysis {
  const [state, setState] = useState<MessageAnalysisState>(() => idle(0));
  const sequence = useRef(0);
  const mounted = useRef(true);
  const active = useRef<AbortController | null>(null);
  const retryRequest = useRef<MessageRequest | null>(null);

  const invalidate = useCallback(() => {
    const sequenceId = ++sequence.current;
    active.current?.abort();
    active.current = null;
    retryRequest.current = null;
    if (mounted.current) setState(idle(sequenceId));
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      invalidate();
    };
  }, [invalidate]);

  const submit = useCallback(async (input: MessageRequest) => {
    if (!mounted.current) return;
    const sequenceId = ++sequence.current;
    active.current?.abort();
    active.current = null;
    retryRequest.current = null;
    let snapshot: MessageRequest | null = null;
    try {
      snapshot = validateMessageRequest(input);
      const controller = new AbortController();
      active.current = controller;
      setState({ sequenceId, submittedText: snapshot.text, inspectLinks: snapshot.inspect_links,
        status: 'loading', result: null, error: null });
      const result = await analyzeMessage(snapshot, controller.signal);
      if (mounted.current && sequence.current === sequenceId && !controller.signal.aborted) {
        setState({ sequenceId, submittedText: snapshot.text, inspectLinks: snapshot.inspect_links,
          status: 'result', result, error: null });
      }
    } catch (error) {
      if (mounted.current && sequence.current === sequenceId) {
        const safeError = error instanceof AnalysisError ? error : new AnalysisError('request_failed');
        retryRequest.current = snapshot;
        setState({ sequenceId, submittedText: snapshot?.text ?? null, inspectLinks: snapshot?.inspect_links ?? null,
          status: 'error', result: null, error: safeError });
      }
    } finally {
      if (sequence.current === sequenceId) active.current = null;
    }
  }, []);

  const retry = useCallback(async () => {
    const input = retryRequest.current;
    if (input) await submit(input);
  }, [submit]);

  return { state, submit, cancel: invalidate, invalidate, retry };
}
