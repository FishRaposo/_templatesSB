use std::env;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn trace_path() -> String {
    env::var("TASK_TRACE_PATH").unwrap_or_else(|_| "artifacts/task-trace.jsonl".to_string())
}

pub fn emit(mut event: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let p = trace_path();
    if !event.get("ts").is_some() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        if let Some(obj) = event.as_object_mut() {
            obj.insert("ts".to_string(), serde_json::Value::from(ts));
        }
    }

    let parent = Path::new(&p).parent().unwrap_or(Path::new("."));
    create_dir_all(parent)?;

    let mut f = OpenOptions::new().create(true).append(true).open(&p)?;
    writeln!(f, "{}", event.to_string())?;
    Ok(())
}
