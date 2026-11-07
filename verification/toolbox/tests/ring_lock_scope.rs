//! Source-level checks for the production Ring object-table interval.
//! Parsing source text is not a proof, but it catches accidental calls to a
//! non-reentrant table accessor or a task-blocking primitive in locked helpers.
use std::collections::BTreeMap;

const RING_SOURCE: &str = include_str!("../../../kernel/src/ring.rs");

fn top_level_functions(source: &str) -> BTreeMap<String, String> {
    let mut functions = BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    for line in source.lines() {
        let header = line.starts_with("fn ")
            || line.starts_with("pub fn ")
            || line.starts_with("pub(crate) fn ")
            || line.starts_with("pub(super) fn ");
        if header {
            if let Some((name, body)) = current.take() {
                functions.insert(name, body);
            }
            if let Some(at) = line.find("fn ") {
                let rest = &line[at + 3..];
                if let Some(end) = rest.find('(') {
                    current = Some((rest[..end].trim().to_owned(), format!("{line}\n")));
                }
            }
        } else if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some((name, body)) = current {
        functions.insert(name, body);
    }
    functions
}

fn violations(source: &str) -> Vec<String> {
    const FORBIDDEN: &[&str] = &[
        "kobj::with",
        "sched::yield",
        "sched::pause",
        "sched::sleep",
        "sched::block_",
        "proc::block_step",
        "copy_to_user(",
        "copy_from_user(",
        "kprint!",
        "kprintln!",
    ];
    top_level_functions(source)
        .into_iter()
        .filter(|(name, _)| name.ends_with("_in") || name == "account_backend_release")
        .flat_map(|(name, body)| {
            FORBIDDEN
                .iter()
                .filter(move |needle| body.contains(**needle))
                .map(move |needle| format!("{name}: {needle}"))
        })
        .collect()
}

#[test]
fn locked_ring_helpers_do_not_reenter_the_table_or_block() {
    let functions = top_level_functions(RING_SOURCE);
    for required in [
        "run_backend_in",
        "progress_backends_in",
        "settle_in",
        "close_in",
        "kernel_cancel_in",
        "deliver_waiter_in",
        "complete_waiter_in",
        "poll_subscription_in",
    ] {
        assert!(functions.contains_key(required), "locked helper {required} disappeared");
    }
    assert!(
        functions.keys().filter(|name| name.ends_with("_in")).count() >= 25,
        "source parser did not find the locked helper set"
    );
    assert_eq!(violations(RING_SOURCE), Vec::<String>::new());
}

#[test]
fn source_audit_negative_detects_reentry_and_blocking() {
    let bad = r#"
fn nested_in(t: &mut Table) {
    kobj::with(|again| reject(again));
}
fn blocker_in() {
    sched::pause();
}
"#;
    let found = violations(bad);
    assert!(found.iter().any(|v| v.contains("nested_in: kobj::with")));
    assert!(found.iter().any(|v| v.contains("blocker_in: sched::pause")));
}
