//! Progress tracking independent of Tokio, so blocked workers can still be diagnosed.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

const STALLED_AFTER: Duration = Duration::from_secs(5);
const REPEAT_AFTER: Duration = Duration::from_secs(30);
static OPERATIONS: OnceLock<Mutex<Operations>> = OnceLock::new();

struct Operations {
    next_id: u64,
    pending: HashMap<u64, Pending>,
}

struct Pending {
    operation: &'static str,
    context: String,
    stage: &'static str,
    started: Instant,
    stage_started: Instant,
    last_warning: Option<Instant>,
}

fn operations() -> &'static Mutex<Operations> {
    OPERATIONS.get_or_init(|| {
        Mutex::new(Operations {
            next_id: 1,
            pending: HashMap::new(),
        })
    })
}

pub struct Operation(u64);

impl Operation {
    // Only pass identifiers here, never request bodies, passwords or tokens.
    pub fn new(operation: &'static str, context: String) -> Self {
        let now = Instant::now();
        let mut registry = operations().lock().unwrap_or_else(|e| e.into_inner());
        let id = registry.next_id;
        registry.next_id = id.wrapping_add(1);
        registry.pending.insert(
            id,
            Pending {
                operation,
                context,
                stage: "start",
                started: now,
                stage_started: now,
                last_warning: None,
            },
        );
        Self(id)
    }

    pub fn stage(&self, stage: &'static str) {
        if let Some(pending) = operations()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .get_mut(&self.0)
        {
            pending.stage = stage;
            pending.stage_started = Instant::now();
            pending.last_warning = None;
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        let pending = operations()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .remove(&self.0);
        if let Some(pending) = pending
            && pending.started.elapsed() >= Duration::from_secs(1)
        {
            log::warn!(
                "diagnostic operation ended id={} operation={} stage={} elapsed_ms={} {} (completion/error/cancellation)",
                self.0,
                pending.operation,
                pending.stage,
                pending.started.elapsed().as_millis(),
                pending.context,
            );
        }
    }
}

fn collect_warnings(pending: &mut HashMap<u64, Pending>, now: Instant) -> Vec<String> {
    let mut warnings = Vec::new();
    for (id, entry) in pending {
        if now.duration_since(entry.stage_started) >= STALLED_AFTER
            && entry
                .last_warning
                .is_none_or(|last| now.duration_since(last) >= REPEAT_AFTER)
        {
            entry.last_warning = Some(now);
            warnings.push(format!(
                "diagnostic operation stalled id={id} operation={} stage={} elapsed_ms={} stage_elapsed_ms={} {}",
                entry.operation, entry.stage, now.duration_since(entry.started).as_millis(),
                now.duration_since(entry.stage_started).as_millis(), entry.context,
            ));
        }
    }
    warnings
}

/// Call from within the running Tokio runtime, after logging is configured.
pub fn start_watchdog() {
    static START: Once = Once::new();
    static HEARTBEAT: AtomicU32 = AtomicU32::new(0);
    START.call_once(|| {
        let thread = std::thread::Builder::new()
            .name("diagnostic-watchdog".into())
            .spawn(|| {
                let mut heartbeat = HEARTBEAT.load(Ordering::Relaxed);
                let mut last_progress = Instant::now();
                let mut last_warning = None;
                loop {
                    std::thread::sleep(STALLED_AFTER);
                    let now = Instant::now();
                    let warnings = {
                        let mut registry = operations().lock().unwrap_or_else(|e| e.into_inner());
                        collect_warnings(&mut registry.pending, now)
                    };
                    // Never call the logger while holding the diagnostics registry lock.
                    for warning in warnings {
                        log::warn!("{warning}");
                    }
                    let current = HEARTBEAT.load(Ordering::Relaxed);
                    if current != heartbeat {
                        if last_warning.is_some() {
                            log::warn!("diagnostic Tokio heartbeat recovered stalled_ms={}", now.duration_since(last_progress).as_millis());
                        }
                        heartbeat = current;
                        last_progress = now;
                        last_warning = None;
                    } else if now.duration_since(last_progress) >= REPEAT_AFTER
                        && last_warning.is_none_or(|last| now.duration_since(last) >= REPEAT_AFTER)
                    {
                        log::error!("diagnostic Tokio heartbeat stalled elapsed_ms={} possible worker blocking/deadlock or severe load", now.duration_since(last_progress).as_millis());
                        last_warning = Some(now);
                    }
                }
            });
        if let Err(error) = thread {
            log::error!("diagnostic watchdog start failed: {error}");
            return;
        }
        tokio::spawn(async {
            loop {
                HEARTBEAT.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        log::info!("diagnostic watchdog started: operation_stall_secs=5 runtime_stall_secs=30 repeat_secs=30");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_updates_stage_and_cleans_up_after_early_return() {
        let id;
        {
            let operation = Operation::new("test", "device_id=test".into());
            id = operation.0;
            operation.stage("wait_lease_state");
            let registry = operations().lock().unwrap();
            let pending = registry.pending.get(&id).unwrap();
            assert_eq!(pending.stage, "wait_lease_state");
            assert!(pending.last_warning.is_none());
        }
        assert!(!operations().lock().unwrap().pending.contains_key(&id));
    }

    #[test]
    fn stalled_operations_report_context_and_throttle_repeated_warnings() {
        let start = Instant::now();
        let mut pending = HashMap::from([(
            7,
            Pending {
                operation: "register",
                context: "network_code=test device_id=device".into(),
                stage: "wait_mutation_lock",
                started: start,
                stage_started: start,
                last_warning: None,
            },
        )]);
        assert!(collect_warnings(&mut pending, start + Duration::from_secs(4)).is_empty());
        let warnings = collect_warnings(&mut pending, start + STALLED_AFTER);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("stage=wait_mutation_lock"));
        assert!(warnings[0].contains("network_code=test device_id=device"));
        assert!(collect_warnings(&mut pending, start + Duration::from_secs(34)).is_empty());
        assert_eq!(
            collect_warnings(&mut pending, start + Duration::from_secs(35)).len(),
            1
        );
    }
}
