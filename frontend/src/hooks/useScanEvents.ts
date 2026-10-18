import { useEffect, useRef } from 'react';
import { api } from '../api';

export interface ProgressEventData {
  stage: string | null;
  percent: number | null;
  checks_run: number;
  findings_so_far: number;
  elapsed_s: number;
  message?: string | null;
}

interface Handlers {
  onProgress: (d: ProgressEventData) => void;
  onDone: (d: { scan_id: string }) => void;
  onError: (d: { message: string }) => void;
}

/**
 * Subscribes to GET /api/scans/{id}/events (Server-Sent Events).
 * Named events: progress | done | error.
 */
export function useScanEvents(scanId: string | undefined, handlers: Handlers): void {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    if (!scanId) return;
    const source = new EventSource(api.eventsUrl(scanId));

    const parse = (e: MessageEvent, fallback: object) => {
      try {
        return { ...fallback, ...JSON.parse(e.data as string) };
      } catch {
        return fallback;
      }
    };

    const onProgress = (e: MessageEvent) => {
      handlersRef.current.onProgress(
        parse(e, { stage: null, percent: null, checks_run: 0, findings_so_far: 0, elapsed_s: 0 }) as ProgressEventData,
      );
    };
    const onDone = (e: MessageEvent) => {
      handlersRef.current.onDone(parse(e, { scan_id: scanId }) as { scan_id: string });
    };
    const onErrorEvent = (e: MessageEvent) => {
      // Named `error` event from the server carries data; a bare EventSource
      // transport failure has no data.
      if (e.data) {
        handlersRef.current.onError(parse(e, { message: 'Unknown scan error' }) as { message: string });
      }
    };

    source.addEventListener('progress', onProgress as EventListener);
    source.addEventListener('done', onDone as EventListener);
    source.addEventListener('error', onErrorEvent as EventListener);

    return () => {
      source.removeEventListener('progress', onProgress as EventListener);
      source.removeEventListener('done', onDone as EventListener);
      source.removeEventListener('error', onErrorEvent as EventListener);
      source.close();
    };
  }, [scanId]);
}
