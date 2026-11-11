import { AnalysisError, CLIENT_REQUEST_TIMEOUT_MS, parseAnalysisResponse, validateMessageRequest } from './analysis';
import type { MessageRequest, MessageResponse } from './analysis';

/** NEXT_PUBLIC_* values are inlined at build time (see the web Dockerfile build arg). */
const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  process.env.NEXT_PUBLIC_API_BASE ||
  'http://localhost:8000';

/** Public, ephemeral scan path: unrelated saved account credentials stay private. */
export async function analyzeMessage(input: MessageRequest, signal: AbortSignal): Promise<MessageResponse> {
  const payload = validateMessageRequest(input);
  if (signal.aborted) throw new AnalysisError('cancelled');
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort();
  signal.addEventListener('abort', cancel, { once: true });
  let stopRequest!: () => void;
  const stopped = new Promise<never>((_resolve, reject) => {
    stopRequest = () => reject(new AnalysisError(timedOut ? 'timeout' : 'cancelled'));
    controller.signal.addEventListener('abort', stopRequest, { once: true });
  });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, CLIENT_REQUEST_TIMEOUT_MS);
  try {
    const operation = (async () => {
      const res = await fetch(`${API_BASE}/v1/analyze-message`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload), signal: controller.signal,
        credentials: 'omit', cache: 'no-store',
      });
      if (!res.ok) {
        const code = res.status === 429 ? 'rate_limit_exceeded'
          : res.status === 503 ? 'analysis_unavailable'
          : res.status === 413 || res.status === 422 ? 'invalid_request' : 'request_failed';
        throw new AnalysisError(code);
      }
      if (!res.headers.get('Content-Type')?.toLowerCase().includes('application/json')) {
        throw new AnalysisError('invalid_response');
      }
      let value: unknown;
      try { value = await res.json(); } catch { throw new AnalysisError('invalid_response'); }
      return parseAnalysisResponse(value);
    })();
    return await Promise.race([operation, stopped]);
  } catch (error) {
    if (error instanceof AnalysisError) throw error;
    if (controller.signal.aborted) throw new AnalysisError(timedOut ? 'timeout' : 'cancelled');
    throw new AnalysisError('network_error');
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', cancel);
    controller.signal.removeEventListener('abort', stopRequest);
  }
}
