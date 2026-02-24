import 'dart:convert';
import 'dart:io';

class TaskTrace {
  static String _tracePath() {
    return Platform.environment['TASK_TRACE_PATH'] ?? 'artifacts/task-trace.jsonl';
  }

  static Future<void> emit({
    required String taskId,
    required String type,
    String? name,
    String? key,
    String? table,
    List<String>? keys,
    dynamic value,
    Map<String, dynamic>? fields,
  }) async {
    final filePath = _tracePath();
    final file = File(filePath);
    await file.parent.create(recursive: true);

    final ev = <String, dynamic>{
      'task_id': taskId,
      'type': type,
      'ts': DateTime.now().millisecondsSinceEpoch / 1000.0,
    };

    if (name != null) ev['name'] = name;
    if (key != null) ev['key'] = key;
    if (table != null) ev['table'] = table;
    if (keys != null) ev['keys'] = keys;
    if (value != null) ev['value'] = value;
    if (fields != null) ev.addAll(fields);

    await file.writeAsString('${jsonEncode(ev)}\n', mode: FileMode.append, flush: true);
  }

  static Future<void> emitEvent(String taskId, String name, {Map<String, dynamic>? fields}) {
    return emit(taskId: taskId, type: 'event.emit', name: name, fields: fields);
  }

  static Future<void> dbWrite(String taskId, String table, {Map<String, dynamic>? fields}) {
    return emit(taskId: taskId, type: 'db.write', table: table, fields: fields);
  }

  static Future<void> taskReturn(String taskId, List<String> keys, {Map<String, dynamic>? fields}) {
    return emit(taskId: taskId, type: 'task.return', keys: keys, fields: fields);
  }

  static Future<void> logEmit(String taskId, String key, {Map<String, dynamic>? fields}) {
    return emit(taskId: taskId, type: 'log.emit', key: key, fields: fields);
  }

  static Future<void> metricEmit(String taskId, String name, {dynamic value, Map<String, dynamic>? fields}) {
    return emit(taskId: taskId, type: 'metric.emit', name: name, value: value, fields: fields);
  }
}
