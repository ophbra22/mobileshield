'use client';

import { ScanForm } from './ScanForm';
import type { MessageRequest } from '@/lib/analysis';

/** Compatibility entry point for the same message form; no legacy URL verdicts. */
interface Props { onSubmit: (request: MessageRequest) => void; onInvalidate: () => void; loading: boolean }
export function AnalyzeForm(props: Props) { return <ScanForm {...props} />; }
