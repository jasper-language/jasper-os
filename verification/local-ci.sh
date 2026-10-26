#!/usr/bin/env bash
# Author: chatgpt. Run only inside the build VM via vm-run.sh.
# The ten-minute Jasper automation invokes this gate; unchanged inputs are cached.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p evidence/local-ci
exec 9>evidence/local-ci/runner.lock
flock -n 9 || { echo 'Local CI already running'; exit 75; }
manifest=$(mktemp)
manifest_after=$(mktemp)
trap 'rm -f "$manifest" "$manifest_after"' EXIT
manifest_inputs() {
    find kernel-core kernel abi user verification tools/krn1 .cargo -type d \( -name __pycache__ -o -name target -o -name corpus -o -name artifacts \) -prune -o -type f -print0 | sort -z | xargs -0 sha256sum
    sha256sum Cargo.toml Cargo.lock rust-toolchain.toml
}
manifest_inputs > "$manifest"
key=$(sha256sum "$manifest" | cut -d' ' -f1)
if [[ -f evidence/local-ci/$key/PASS ]]; then
    echo "Local CI unchanged and passed: $key"
    exit 0
fi
run="evidence/local-ci/$key"
mkdir -p "$run"
cp "$manifest" "$run/inputs.sha256"
# A failed/incomplete attempt has no PASS marker and is retried on the next wakeup.
rm -f "$run/PASS"
{
    date -u +%FT%TZ
    cargo test --manifest-path verification/toolbox/Cargo.toml --locked
    bash verification/toolbox/run-negative-transfer.sh
    bash scripts/abi-freeze.sh --check-reservations
    cargo test -p kernel-core --test extension_abi
    bash verification/run-pi-isolated-exit-tlc.sh
    if bash verification/run-pi-isolated-exit-tlc.sh pi_isolated_exit_missing_outgoing.cfg > "$run/pi-isolated-exit-negative.log" 2>&1; then exit 1; fi
    grep -q "Invariant Safety is violated" "$run/pi-isolated-exit-negative.log"
    bash verification/run-group-membership-tlc.sh
    if bash verification/run-group-membership-tlc.sh group_membership_stale.cfg > "$run/group-membership-negative.log" 2>&1; then exit 1; fi
    grep -q "Invariant Safety is violated" "$run/group-membership-negative.log"
    bash verification/run-deadline-owner-tlc.sh
    for variant in move notify remote; do
        if bash verification/run-deadline-owner-tlc.sh "deadline_owner_${variant}.cfg" > "$run/deadline-owner-${variant}.log" 2>&1; then
            echo "Deadline ownership negative model unexpectedly passed: $variant"; exit 1
        fi
        grep -q "Invariant Safety is violated" "$run/deadline-owner-${variant}.log"
    done
    bash verification/run-wake-mailbox-tlc.sh
    for variant in stale full; do
        if bash verification/run-wake-mailbox-tlc.sh "wake_mailbox_${variant}.cfg" > "$run/wake-mailbox-${variant}.log" 2>&1; then
            echo "Wake mailbox negative model unexpectedly passed: $variant"; exit 1
        fi
        grep -q "Invariant Safety is violated" "$run/wake-mailbox-${variant}.log"
    done
    bash verification/run-leaf-membership-tlc.sh
    if bash verification/run-leaf-membership-tlc.sh leaf_membership_missing_caller.cfg > "$run/leaf-membership-negative.log" 2>&1; then
        echo "Missing registration leaf unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/leaf-membership-negative.log"
    bash verification/run-churn-barrier-tlc.sh
    if bash verification/run-churn-barrier-tlc.sh churn_barrier_early.cfg > "$run/churn-barrier-early.log" 2>&1; then
        echo "Premature churn release unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/churn-barrier-early.log"
    bash verification/run-subscription-snapshot-tlc.sh subscription_snapshot.cfg
    if bash verification/run-subscription-snapshot-tlc.sh subscription_split.cfg > "$run/subscription_split.log" 2>&1; then
        echo "Negative model unexpectedly passed: subscription_split.cfg"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/subscription_split.log"
    if bash verification/run-subscription-snapshot-tlc.sh subscription_silent_overflow.cfg > "$run/subscription_silent_overflow.log" 2>&1; then
        echo "Negative model unexpectedly passed: subscription_silent_overflow.cfg"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/subscription_silent_overflow.log"
    bash verification/run-subscription-broadcast-tlc.sh subscription_broadcast_events.cfg
    bash verification/run-subscription-broadcast-tlc.sh subscription_broadcast_state.cfg
    bash verification/run-subscription-broadcast-tlc.sh subscription_broadcast_count.cfg
    if bash verification/run-subscription-broadcast-tlc.sh subscription_broadcast_drop.cfg > "$run/subscription_broadcast_drop.log" 2>&1; then
        echo "Negative model unexpectedly passed: subscription_broadcast_drop.cfg"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/subscription_broadcast_drop.log"
    bash verification/run-subscription-lifetime-tlc.sh subscription_lifetime.cfg
    if bash verification/run-subscription-lifetime-tlc.sh subscription_lifetime_early.cfg > "$run/subscription_lifetime_early.log" 2>&1; then
        echo "Negative model unexpectedly passed: subscription_lifetime_early.cfg"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/subscription_lifetime_early.log"
    bash verification/run-subscription-wait-tlc.sh subscription_wait.cfg
    if bash verification/run-subscription-wait-tlc.sh subscription_wait_duplicate.cfg > "$run/subscription_wait_duplicate.log" 2>&1; then
        echo "Negative model unexpectedly passed: subscription_wait_duplicate.cfg"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/subscription_wait_duplicate.log"
    bash verification/run-subscription-publisher-anchor-tlc.sh subscription_publisher_anchor.cfg
    if bash verification/run-subscription-publisher-anchor-tlc.sh subscription_publisher_no_anchor.cfg > "$run/subscription_publisher_no_anchor.log" 2>&1; then
        echo "Negative model unexpectedly passed: subscription_publisher_no_anchor.cfg"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/subscription_publisher_no_anchor.log"
    bash verification/run-pressure-event-dirty-tlc.sh pressure_event_dirty.cfg
    if bash verification/run-pressure-event-dirty-tlc.sh pressure_event_dirty_late.cfg > "$run/pressure_event_dirty_late.log" 2>&1; then
        echo "Negative model unexpectedly passed: pressure_event_dirty_late.cfg"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/pressure_event_dirty_late.log"
    bash verification/run-budget-observation-tlc.sh
    if bash verification/run-budget-observation-tlc.sh budget_observation_rewrite.cfg > "$run/budget-observation-negative.log" 2>&1; then
        echo "Budget cutoff rewrite unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/budget-observation-negative.log"
    bash verification/run-shm-page-lifetime-tlc.sh
    for variant in no_ack no_pin; do
        if bash verification/run-shm-page-lifetime-tlc.sh "shm_page_lifetime_${variant}.cfg" > "$run/shm-lifetime-${variant}.log" 2>&1; then
            echo "SHM lifetime negative unexpectedly passed: $variant"; exit 1
        fi
        grep -q "Invariant Safety is violated" "$run/shm-lifetime-${variant}.log"
    done
    bash verification/run-ring-wait-deadline-tlc.sh
    if bash verification/run-ring-wait-deadline-tlc.sh ring_wait_deadline_timeout_first.cfg > "$run/ring-wait-deadline-negative.log" 2>&1; then
        echo "Timeout-before-ready unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/ring-wait-deadline-negative.log"
    bash verification/run-irq-event-binding-tlc.sh
    if bash verification/run-irq-event-binding-tlc.sh irq_event_binding_stale.cfg > "$run/irq-event-binding-stale.log" 2>&1; then
        echo "Stale IRQ binding unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/irq-event-binding-stale.log"
    bash verification/run-ring-wait-lifecycle-tlc.sh
    for variant in stale leak; do
        if bash verification/run-ring-wait-lifecycle-tlc.sh "ring_wait_lifecycle_${variant}.cfg" > "$run/ring-wait-lifecycle-${variant}.log" 2>&1; then
            echo "Ring wait lifecycle negative unexpectedly passed: $variant"; exit 1
        fi
        grep -q "Invariant Safety is violated" "$run/ring-wait-lifecycle-${variant}.log"
    done
    bash verification/run-ring-wait-enroll-tlc.sh
    if bash verification/run-ring-wait-enroll-tlc.sh ring_wait_enroll_split.cfg > "$run/ring-wait-enroll-split.log" 2>&1; then
        echo "Split event-wait enrollment unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/ring-wait-enroll-split.log"
    bash verification/run-shared-tick-credit-tlc.sh
    for variant in duplicate undrained; do
        if bash verification/run-shared-tick-credit-tlc.sh "shared_tick_credit_${variant}.cfg" > "$run/shared-credit-${variant}.log" 2>&1; then
            echo "Shared tick credit negative unexpectedly passed: $variant"; exit 1
        fi
        grep -q "Invariant Safety is violated" "$run/shared-credit-${variant}.log"
    done
    bash verification/run-tick-lease-tlc.sh
    if bash verification/run-tick-lease-tlc.sh tick_lease_negative.cfg > "$run/tick-lease-negative.log" 2>&1; then
        echo "Undrained local tick negative model unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/tick-lease-negative.log"
    bash verification/run-task-index-publish-tlc.sh
    if bash verification/run-task-index-publish-tlc.sh task_index_publish_negative.cfg > "$run/task-index-publish-negative.log" 2>&1; then
        echo "Unremoved historical label negative model unexpectedly passed"; exit 1
    fi
    grep -q "Invariant IndexMatches is violated" "$run/task-index-publish-negative.log"
    bash verification/run-task-lifecycle-tlc.sh
    if bash verification/run-task-lifecycle-tlc.sh task_lifecycle_negative.cfg > "$run/task-lifecycle-negative.log" 2>&1; then
        echo "Stale-generation negative model unexpectedly passed"; exit 1
    fi
    grep -q "Invariant Safety is violated" "$run/task-lifecycle-negative.log"
    bash verification/run-tlb-start-tlc.sh
    if bash verification/run-tlb-start-tlc.sh tlb_test_start_negative.cfg > "$run/tlb-start-negative.log" 2>&1; then
        echo 'Writer-before-peer negative model unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant WriterHasPeer is violated' "$run/tlb-start-negative.log"
    bash verification/run-yield-gate-tlc.sh
    if bash verification/run-yield-gate-tlc.sh yield_gate_negative.cfg > "$run/yield-negative.log" 2>&1; then
        echo 'Undrained watchdog negative model unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safe is violated' "$run/yield-negative.log"
    bash verification/run-rt-refill-tlc.sh
    bash verification/run-deadline-tlc.sh
    bash verification/run-ticket-tlc.sh
    bash verification/run-soak-tlc.sh
    bash verification/run-tlb-quarantine-tlc.sh
    if bash verification/run-tlb-quarantine-tlc.sh tlb_timeout_quarantine_negative.cfg > "$run/tlb-quarantine-negative.log" 2>&1; then
        echo 'Unsafe TLB release unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant NoReleaseWhileStale is violated' "$run/tlb-quarantine-negative.log"
    bash verification/run-rt-partition-admission-tlc.sh
    if bash verification/run-rt-partition-admission-tlc.sh rt_partition_admission_drop.cfg > "$run/rt-partition-admission-negative.log" 2>&1; then
        echo 'RT negative unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/rt-partition-admission-negative.log"
    bash verification/run-rt-reentry-debt-tlc.sh
    if bash verification/run-rt-reentry-debt-tlc.sh rt_reentry_debt_refresh.cfg > "$run/rt-reentry-debt-negative.log" 2>&1; then
        echo 'RT negative unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/rt-reentry-debt-negative.log"
    bash verification/run-timer-deadline-recheck-tlc.sh
    if bash verification/run-timer-deadline-recheck-tlc.sh timer_deadline_recheck_early.cfg > "$run/timer-deadline-recheck-negative.log" 2>&1; then
        echo 'Timer negative unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/timer-deadline-recheck-negative.log"
    bash verification/run-elapsed-irq-credit-tlc.sh
    if bash verification/run-elapsed-irq-credit-tlc.sh elapsed_irq_credit_per_irq.cfg > "$run/elapsed-irq-credit-negative.log" 2>&1; then
        echo 'Timer negative unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/elapsed-irq-credit-negative.log"
    bash verification/run-rt-partition-edf-tlc.sh
    if bash verification/run-rt-partition-edf-tlc.sh rt_partition_edf_reverse.cfg > "$run/rt-partition-edf-negative.log" 2>&1; then
        echo 'RT negative unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/rt-partition-edf-negative.log"
    bash verification/run-rt-control-authority-tlc.sh
    if bash verification/run-rt-control-authority-tlc.sh rt_control_authority_split.cfg > "$run/rt-control-authority-negative.log" 2>&1; then
        echo 'RT negative unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/rt-control-authority-negative.log"
    bash verification/run-rt-worker-teardown-tlc.sh
    if bash verification/run-rt-worker-teardown-tlc.sh rt_worker_teardown_early.cfg > "$run/rt-worker-teardown-negative.log" 2>&1; then
        echo 'Early worker stop unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/rt-worker-teardown-negative.log"
    bash verification/run-sleep-registration-tlc.sh
    if bash verification/run-sleep-registration-tlc.sh sleep_registration_split.cfg > "$run/sleep-registration-negative.log" 2>&1; then
        echo 'Split deadline registration unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/sleep-registration-negative.log"
    bash verification/run-wake-pair-tlc.sh
    if bash verification/run-wake-pair-tlc.sh wake_pair_duplicate.cfg > "$run/wake-pair-negative.log" 2>&1; then
        echo 'Repeated wake completion unexpectedly passed'; exit 1
    fi
    grep -q 'Invariant Safety is violated' "$run/wake-pair-negative.log"
    bash verification/run-rt3-mutex-lifecycle-tlc.sh
    bash verification/run-rt3-ring-donation-tlc.sh
    bash verification/run-worker-count-tlc.sh
    bash verification/run-env0-tlc.sh
    bash verification/run-ring-fv1-tlc.sh
    bash verification/run-kani.sh
    cargo test -p kernel-core --lib --no-run --message-format=json > "$run/core-build.jsonl"
    python3 verification/snapshot-core-test.py "$run"
    cargo test -p kernel-core -- --format=json -Z unstable-options
    python3 -m unittest discover -s tools/krn1 -p 'test_*.py' -v
    manifest_inputs > "$manifest_after"
    cmp "$manifest" "$manifest_after"
} > "$run/run.log" 2>&1
cp -a evidence/fv1 "$run/proof"
printf '%s\n' "$key" > "$run/PASS"
printf '%s\n' "$key" > evidence/local-ci/latest-pass.txt
printf 'Local CI PASS: %s\n' "$key"
