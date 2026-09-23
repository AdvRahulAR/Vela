export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

export interface StructuredLogEntry {
  level: LogLevel;
  service: string;
  operation: string;
  duration_ms?: number;
  context?: Record<string, unknown>;
  error?: string;
  timestamp?: string;
}

export class Logger {
  private enabled: boolean;
  private serviceName: string;

  constructor(serviceName = 'vela', enabled = false) {
    this.serviceName = serviceName;
    this.enabled = enabled;
  }

  log(entry: Omit<StructuredLogEntry, 'service' | 'timestamp'>): void {
    if (!this.enabled && entry.level !== 'error') return;

    const payload: StructuredLogEntry = {
      timestamp: new Date().toISOString(),
      service: this.serviceName,
      ...entry,
    };

    const serialized = JSON.stringify(payload);
    if (entry.level === 'error') {
      console.error(serialized);
    } else if (entry.level === 'warn') {
      console.warn(serialized);
    } else {
      console.log(serialized);
    }
  }

  info(operation: string, context?: Record<string, unknown>, duration_ms?: number): void {
    this.log({ level: 'info', operation, context, duration_ms });
  }

  warn(operation: string, context?: Record<string, unknown>): void {
    this.log({ level: 'warn', operation, context });
  }

  error(operation: string, error: unknown, context?: Record<string, unknown>): void {
    const errorMsg = error instanceof Error ? error.message : String(error);
    this.log({ level: 'error', operation, error: errorMsg, context });
  }
}
