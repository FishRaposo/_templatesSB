const fs = require('fs');
const path = require('path');

function tracePath() {
  return process.env.TASK_TRACE_PATH || path.join('artifacts', 'task-trace.jsonl');
}

function writeEvent(ev) {
  const p = tracePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const event = { ...ev, ts: ev.ts ?? Date.now() / 1000 };
  fs.appendFileSync(p, JSON.stringify(event) + '\n', { encoding: 'utf8' });
}

function emit({ task_id, type, name, key, table, keys, value, fields }) {
  const ev = { task_id, type };
  if (name !== undefined) ev.name = name;
  if (key !== undefined) ev.key = key;
  if (table !== undefined) ev.table = table;
  if (keys !== undefined) ev.keys = keys;
  if (value !== undefined) ev.value = value;
  if (fields && typeof fields === 'object') Object.assign(ev, fields);
  writeEvent(ev);
}

function emitEvent(task_id, name, fields) {
  emit({ task_id, type: 'event.emit', name, fields });
}

function dbWrite(task_id, table, fields) {
  emit({ task_id, type: 'db.write', table, fields });
}

function taskReturn(task_id, keys, fields) {
  emit({ task_id, type: 'task.return', keys, fields });
}

function logEmit(task_id, key, fields) {
  emit({ task_id, type: 'log.emit', key, fields });
}

function metricEmit(task_id, name, value, fields) {
  emit({ task_id, type: 'metric.emit', name, value, fields });
}

module.exports = {
  emit,
  emitEvent,
  dbWrite,
  taskReturn,
  logEmit,
  metricEmit,
};
