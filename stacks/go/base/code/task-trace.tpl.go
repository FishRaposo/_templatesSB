package tasktrace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Event map[string]any

func tracePath() string {
	p := os.Getenv("TASK_TRACE_PATH")
	if p == "" {
		p = filepath.Join("artifacts", "task-trace.jsonl")
	}
	return p
}

func Emit(event Event) error {
	p := tracePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if _, ok := event["ts"]; !ok {
		event["ts"] = float64(time.Now().UnixNano()) / 1e9
	}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func EmitEvent(taskID string, name string, fields Event) error {
	ev := Event{"task_id": taskID, "type": "event.emit", "name": name}
	for k, v := range fields {
		ev[k] = v
	}
	return Emit(ev)
}

func DBWrite(taskID string, table string, fields Event) error {
	ev := Event{"task_id": taskID, "type": "db.write", "table": table}
	for k, v := range fields {
		ev[k] = v
	}
	return Emit(ev)
}

func TaskReturn(taskID string, keys []string, fields Event) error {
	ev := Event{"task_id": taskID, "type": "task.return", "keys": keys}
	for k, v := range fields {
		ev[k] = v
	}
	return Emit(ev)
}

func LogEmit(taskID string, key string, fields Event) error {
	ev := Event{"task_id": taskID, "type": "log.emit", "key": key}
	for k, v := range fields {
		ev[k] = v
	}
	return Emit(ev)
}

func MetricEmit(taskID string, name string, value any, fields Event) error {
	ev := Event{"task_id": taskID, "type": "metric.emit", "name": name, "value": value}
	for k, v := range fields {
		ev[k] = v
	}
	return Emit(ev)
}
