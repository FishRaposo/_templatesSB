let fs;
let path;

try {
  fs = require('fs');
  path = require('path');
} catch (_e) {
  fs = null;
  path = null;
}

function tracePath() {
  if (typeof process !== 'undefined' && process.env && process.env.TASK_TRACE_PATH) {
    return process.env.TASK_TRACE_PATH;
  }
  return path ? path.join('artifacts', 'task-trace.jsonl') : 'artifacts/task-trace.jsonl';
}

function writeEvent(ev) {
  if (!fs || !path) {
    return;
  }
  const p = tracePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const event = { ...ev, ts: ev.ts ?? Date.now() / 1000 };
  fs.appendFileSync(p, JSON.stringify(event) + '\n', { encoding: 'utf8' });
}

export function emit({ task_id, type, name, key, table, keys, value, fields }) {
  const ev = { task_id, type };
  if (name !== undefined) ev.name = name;
  if (key !== undefined) ev.key = key;
  if (table !== undefined) ev.table = table;
  if (keys !== undefined) ev.keys = keys;
  if (value !== undefined) ev.value = value;
  if (fields && typeof fields === 'object') Object.assign(ev, fields);
  writeEvent(ev);
}

export function emitEvent(task_id, name, fields) {
  emit({ task_id, type: 'event.emit', name, fields });
}

export function dbWrite(task_id, table, fields) {
  emit({ task_id, type: 'db.write', table, fields });
}

export function taskReturn(task_id, keys, fields) {
  emit({ task_id, type: 'task.return', keys, fields });
}

export function logEmit(task_id, key, fields) {
  emit({ task_id, type: 'log.emit', key, fields });
}

export function metricEmit(task_id, name, value, fields) {
  emit({ task_id, type: 'metric.emit', name, value, fields });
}
