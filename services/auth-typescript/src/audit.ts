import { redactText } from './pii';
import { AuditEvent } from './types';

export class AuthAuditLog {
  private readonly events: AuditEvent[] = [];

  constructor(private readonly maxEvents = 10_000) {}

  record(actor: string, action: string, outcome: 'SUCCESS' | 'FAILURE', details: Record<string, string>, timestamp: number): AuditEvent {
    if (!actor) {
      throw new Error('actor is required');
    }
    const safeDetails: Record<string, string> = {};
    for (const [key, value] of Object.entries(details)) {
      safeDetails[key] = redactText(String(value));
    }
    const event: AuditEvent = { timestamp, actor, action, outcome, details: safeDetails };
    this.events.push(event);
    if (this.events.length > this.maxEvents) {
      this.events.shift();
    }
    return event;
  }

  success(actor: string, action: string, details: Record<string, string>, timestamp: number): AuditEvent {
    return this.record(actor, action, 'SUCCESS', details, timestamp);
  }

  failure(actor: string, action: string, details: Record<string, string>, timestamp: number): AuditEvent {
    return this.record(actor, action, 'FAILURE', details, timestamp);
  }

  all(): readonly AuditEvent[] {
    return this.events;
  }

  forActor(actor: string): AuditEvent[] {
    return this.events.filter((e) => e.actor === actor);
  }

  failuresSince(timestamp: number): AuditEvent[] {
    return this.events.filter((e) => e.outcome === 'FAILURE' && e.timestamp >= timestamp);
  }

  countByAction(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const e of this.events) {
      counts[e.action] = (counts[e.action] ?? 0) + 1;
    }
    return counts;
  }

  toNdjson(): string {
    return this.events.map((e) => JSON.stringify(e)).join('\n');
  }
}
