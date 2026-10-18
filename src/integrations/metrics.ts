import type { AuditEvent } from '../core/audit.js';

/**
 * Prometheus metrics built from audit events (counts only, never values).
 * Labels are bounded: request format, outcome, entity type, tenant.
 */
export class VelaMetrics {
  private readonly counters = new Map<string, number>();
  private latencySum = 0;
  private latencyCount = 0;
  private readonly tenantLabels: boolean;

  /** `tenantLabels`: label series by tenant. Off by default: /metrics needs no token, and tenant names are not public. */
  constructor(opts: { tenantLabels?: boolean } = {}) {
    this.tenantLabels = opts.tenantLabels ?? false;
  }

  private inc(name: string, labels: Record<string, string | undefined>, by = 1): void {
    const l = Object.entries(labels)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => `${k}="${String(v).replace(/["\\\n]/g, '_').slice(0, 64)}"`)
      .join(',');
    const key = `${name}{${l}}`;
    this.counters.set(key, (this.counters.get(key) ?? 0) + by);
  }

  /** Feed one audit event (pass to `vela.onEvent`). */
  readonly record = (e: AuditEvent): void => {
    const tenant = this.tenantLabels ? e.tenant : undefined;
    switch (e.event) {
      case 'vela.request':
        for (const [type, n] of Object.entries(e.entities ?? {})) this.inc('vela_entities_detected_total', { type, tenant }, n);
        for (const [action, n] of Object.entries(e.actions ?? {})) this.inc('vela_values_masked_total', { action, tenant }, n);
        if (e.ner === 'failed_continued') this.inc('vela_ner_failures_total', { outcome: 'continued' });
        break;
      case 'vela.response':
        this.inc('vela_requests_total', { format: e.format, outcome: 'forwarded', tenant });
        for (const [field, n] of Object.entries(e.restore?.kept ?? {})) if (n) this.inc('vela_placeholders_kept_total', { field }, n);
        if (e.latency_ms !== undefined) {
          this.latencySum += e.latency_ms / 1000;
          this.latencyCount++;
        }
        break;
      case 'vela.blocked':
        this.inc('vela_requests_total', { format: e.format ?? 'unknown', outcome: 'blocked', tenant });
        this.inc('vela_blocked_total', { reason: e.error_type });
        break;
      case 'vela.error':
        this.inc('vela_requests_total', { format: e.format ?? 'unknown', outcome: 'error', tenant });
        if (e.error_type === 'VelaRecognizerError') this.inc('vela_ner_failures_total', { outcome: 'blocked' });
        break;
    }
  };

  /** Prometheus text exposition format. */
  render(): string {
    const help: Record<string, string> = {
      vela_requests_total: 'LLM requests handled, by outcome',
      vela_entities_detected_total: 'Personal-data entities detected, by type',
      vela_values_masked_total: 'Unique values masked, by method',
      vela_blocked_total: 'Requests blocked, by reason',
      vela_ner_failures_total: 'NER service failures',
      vela_placeholders_kept_total: 'Placeholders left unrestored by the restore policy',
    };
    const lines: string[] = [];
    const byName = new Map<string, string[]>();
    for (const [key, v] of [...this.counters].sort()) {
      const name = key.slice(0, key.indexOf('{'));
      const series = key.endsWith('{}') ? name : key;
      byName.set(name, [...(byName.get(name) ?? []), `${series} ${v}`]);
    }
    for (const [name, series] of byName) lines.push(`# HELP ${name} ${help[name] ?? name}`, `# TYPE ${name} counter`, ...series);
    lines.push(
      '# HELP vela_request_duration_seconds Time from receiving a request to the end of its response',
      '# TYPE vela_request_duration_seconds summary',
      `vela_request_duration_seconds_sum ${this.latencySum}`,
      `vela_request_duration_seconds_count ${this.latencyCount}`,
    );
    return lines.join('\n') + '\n';
  }
}
