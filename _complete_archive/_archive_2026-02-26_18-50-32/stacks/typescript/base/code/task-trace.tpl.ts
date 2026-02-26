import fs from 'fs';
import path from 'path';

type Fields = Record<string, unknown>;

function tracePath(): string {
  return process.env.TASK_TRACE_PATH || path.join('artifacts', 'task-trace.jsonl');
}

function writeEvent(ev: Record<string, unknown>): void {
  const p = tracePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const event = { ...ev, ts: (ev as any).ts ?? Date.now() / 1000 };
  fs.appendFileSync(p, JSON.stringify(event) + '\n', { encoding: 'utf8' });
}

export function emit(params: {
  task_id: string;
  type: string;
  name?: string;
  key?: string;
  table?: string;
  keys?: string[];
  value?: unknown;
  fields?: Fields;
}): void {
  const { task_id, type, name, key, table, keys, value, fields } = params;
  const ev: Record<string, unknown> = { task_id, type };
  if (name !== undefined) ev.name = name;
  if (key !== undefined) ev.key = key;
  if (table !== undefined) ev.table = table;
  if (keys !== undefined) ev.keys = keys;
  if (value !== undefined) ev.value = value;
  if (fields) Object.assign(ev, fields);
  writeEvent(ev);
}

export function emitEvent(task_id: string, name: string, fields?: Fields): void {
  emit({ task_id, type: 'event.emit', name, fields });
}

export function dbWrite(task_id: string, table: string, fields?: Fields): void {
  emit({ task_id, type: 'db.write', table, fields });
}

export function taskReturn(task_id: string, keys: string[], fields?: Fields): void {
  emit({ task_id, type: 'task.return', keys, fields });
}

export function logEmit(task_id: string, key: string, fields?: Fields): void {
  emit({ task_id, type: 'log.emit', key, fields });
}

export function metricEmit(task_id: string, name: string, value?: unknown, fields?: Fields): void {
  emit({ task_id, type: 'metric.emit', name, value, fields });
}
