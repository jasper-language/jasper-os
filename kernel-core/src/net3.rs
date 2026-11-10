//! Bounded network management, retry and observability contracts.
//!
//! 职责：维护网络接口生命周期、有界指数退避、丢包分类和固定容量状态快照。
//! 边界：不解析报文、不执行 TCP 状态机，也不替代生产安全策略。
//! Responsibility: lifecycle, bounded retry, loss accounting and inspection.
//! Packet parsing, TCP state and production security policy remain elsewhere.

pub const OBSERVATION_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Down,
    Probing,
    Up,
    Degraded,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryDecision {
    Wait {
        attempt: u8,
        delay: u64,
        deadline: u64,
    },
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net3Error {
    InvalidConfig,
    InvalidTransition,
    StaleGeneration,
    RetryExhausted,
    TrafficMismatch,
    CounterOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub max_attempts: u8,
    pub initial_delay: u64,
    pub max_delay: u64,
    pub multiplier: u8,
}

impl BackoffPolicy {
    pub fn validate(self) -> Result<Self, Net3Error> {
        if self.max_attempts == 0
            || self.initial_delay == 0
            || self.max_delay < self.initial_delay
            || self.multiplier < 2
        {
            return Err(Net3Error::InvalidConfig);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    policy: BackoffPolicy,
    attempts: u8,
    last_delay: u64,
    next_deadline: u64,
}

impl Backoff {
    pub fn new(policy: BackoffPolicy) -> Result<Self, Net3Error> {
        Ok(Self {
            policy: policy.validate()?,
            attempts: 0,
            last_delay: 0,
            next_deadline: 0,
        })
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn last_delay(&self) -> u64 {
        self.last_delay
    }

    pub const fn next_deadline(&self) -> u64 {
        self.next_deadline
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
        self.last_delay = 0;
        self.next_deadline = 0;
    }

    pub fn schedule(&mut self, now: u64, entropy: u64) -> RetryDecision {
        if self.attempts >= self.policy.max_attempts {
            return RetryDecision::Exhausted;
        }
        let factor = self
            .policy
            .multiplier
            .saturating_pow(u32::from(self.attempts))
            .max(1);
        let exponential = self
            .policy
            .initial_delay
            .saturating_mul(u64::from(factor))
            .min(self.policy.max_delay);
        let jitter_span = exponential / 8 + 1;
        let delay = exponential
            .saturating_add(entropy % jitter_span)
            .min(self.policy.max_delay);
        self.attempts = self.attempts.saturating_add(1);
        self.last_delay = delay;
        self.next_deadline = now.saturating_add(delay);
        RetryDecision::Wait {
            attempt: self.attempts,
            delay,
            deadline: self.next_deadline,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LossCounters {
    offered: u64,
    delivered: u64,
    transport_lost: u64,
    queue_dropped: u64,
    quota_dropped: u64,
    malformed: u64,
}

impl LossCounters {
    pub const fn offered(self) -> u64 {
        self.offered
    }

    pub const fn delivered(self) -> u64 {
        self.delivered
    }

    pub const fn transport_lost(self) -> u64 {
        self.transport_lost
    }

    pub const fn queue_dropped(self) -> u64 {
        self.queue_dropped
    }

    pub const fn quota_dropped(self) -> u64 {
        self.quota_dropped
    }

    pub const fn malformed(self) -> u64 {
        self.malformed
    }

    pub const fn total_lost(self) -> u64 {
        self.transport_lost
            .saturating_add(self.queue_dropped)
            .saturating_add(self.quota_dropped)
            .saturating_add(self.malformed)
    }

    pub fn account(
        &mut self,
        offered: u64,
        delivered: u64,
        queue_dropped: u64,
        quota_dropped: u64,
        malformed: u64,
    ) -> Result<(), Net3Error> {
        let classified = delivered
            .checked_add(queue_dropped)
            .and_then(|sum| sum.checked_add(quota_dropped))
            .and_then(|sum| sum.checked_add(malformed))
            .ok_or(Net3Error::CounterOverflow)?;
        if classified > offered {
            return Err(Net3Error::TrafficMismatch);
        }
        let transport_lost = offered - classified;
        let next = LossCounters {
            offered: self
                .offered
                .checked_add(offered)
                .ok_or(Net3Error::CounterOverflow)?,
            delivered: self
                .delivered
                .checked_add(delivered)
                .ok_or(Net3Error::CounterOverflow)?,
            transport_lost: self
                .transport_lost
                .checked_add(transport_lost)
                .ok_or(Net3Error::CounterOverflow)?,
            queue_dropped: self
                .queue_dropped
                .checked_add(queue_dropped)
                .ok_or(Net3Error::CounterOverflow)?,
            quota_dropped: self
                .quota_dropped
                .checked_add(quota_dropped)
                .ok_or(Net3Error::CounterOverflow)?,
            malformed: self
                .malformed
                .checked_add(malformed)
                .ok_or(Net3Error::CounterOverflow)?,
        };
        let accounted = next
            .delivered
            .checked_add(next.total_lost())
            .ok_or(Net3Error::CounterOverflow)?;
        if accounted != next.offered {
            return Err(Net3Error::TrafficMismatch);
        }
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub sequence: u64,
    pub generation: u32,
    pub state: LinkState,
    pub retry_attempts: u8,
    pub last_retry_delay: u64,
    pub next_retry_deadline: u64,
    pub loss: LossCounters,
    pub lifecycle_events: u64,
}

pub struct ObservationLog {
    entries: [Option<StatusSnapshot>; OBSERVATION_CAPACITY],
    head: usize,
    len: usize,
    next_sequence: u64,
    dropped: u64,
}

impl ObservationLog {
    pub const fn new() -> Self {
        Self {
            entries: [None; OBSERVATION_CAPACITY],
            head: 0,
            len: 0,
            next_sequence: 1,
            dropped: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn publish(&mut self, mut snapshot: StatusSnapshot) -> bool {
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        };
        if self.next_sequence == 0 || self.len == OBSERVATION_CAPACITY {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        snapshot.sequence = self.next_sequence;
        self.next_sequence = next_sequence;
        let slot = (self.head + self.len) % OBSERVATION_CAPACITY;
        self.entries[slot] = Some(snapshot);
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> Option<StatusSnapshot> {
        if self.len == 0 {
            return None;
        }
        let snapshot = self.entries[self.head].take();
        self.head = (self.head + 1) % OBSERVATION_CAPACITY;
        self.len -= 1;
        snapshot
    }

    pub fn reset(&mut self) {
        self.head = 0;
        self.len = 0;
        self.entries.fill(None);
    }
}

impl Default for ObservationLog {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NetworkManager {
    generation: u32,
    state: LinkState,
    backoff: Backoff,
    loss: LossCounters,
    observations: ObservationLog,
    lifecycle_events: u64,
}

impl NetworkManager {
    pub fn new(policy: BackoffPolicy) -> Result<Self, Net3Error> {
        Ok(Self {
            generation: 0,
            state: LinkState::Down,
            backoff: Backoff::new(policy)?,
            loss: LossCounters::default(),
            observations: ObservationLog::new(),
            lifecycle_events: 0,
        })
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn state(&self) -> LinkState {
        self.state
    }

    pub const fn loss(&self) -> LossCounters {
        self.loss
    }

    pub const fn observations(&self) -> &ObservationLog {
        &self.observations
    }

    pub fn observations_mut(&mut self) -> &mut ObservationLog {
        &mut self.observations
    }

    pub fn start(&mut self) -> Result<u32, Net3Error> {
        if !matches!(
            self.state,
            LinkState::Down | LinkState::Failed | LinkState::Stopped
        ) {
            return Err(Net3Error::InvalidTransition);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Net3Error::CounterOverflow)?;
        self.state = LinkState::Probing;
        self.backoff.reset();
        self.lifecycle_events = self.lifecycle_events.saturating_add(1);
        Ok(self.generation)
    }

    pub fn probe_succeeded(&mut self, generation: u32) -> Result<(), Net3Error> {
        self.check_generation(generation)?;
        if self.state != LinkState::Probing && self.state != LinkState::Degraded {
            return Err(Net3Error::InvalidTransition);
        }
        self.state = LinkState::Up;
        self.backoff.reset();
        self.lifecycle_events = self.lifecycle_events.saturating_add(1);
        Ok(())
    }

    pub fn probe_failed(
        &mut self,
        generation: u32,
        now: u64,
        entropy: u64,
        fatal: bool,
    ) -> Result<RetryDecision, Net3Error> {
        self.check_generation(generation)?;
        if !matches!(self.state, LinkState::Probing | LinkState::Degraded) {
            return Err(Net3Error::InvalidTransition);
        }
        self.lifecycle_events = self.lifecycle_events.saturating_add(1);
        if fatal {
            self.state = LinkState::Failed;
            return Ok(RetryDecision::Exhausted);
        }
        let decision = self.backoff.schedule(now, entropy);
        self.state = if decision == RetryDecision::Exhausted {
            LinkState::Failed
        } else {
            LinkState::Degraded
        };
        Ok(decision)
    }

    pub fn link_lost(&mut self, generation: u32) -> Result<(), Net3Error> {
        self.check_generation(generation)?;
        if self.state != LinkState::Up {
            return Err(Net3Error::InvalidTransition);
        }
        self.state = LinkState::Degraded;
        self.lifecycle_events = self.lifecycle_events.saturating_add(1);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<u32, Net3Error> {
        if self.state == LinkState::Stopped {
            return Ok(self.generation);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Net3Error::CounterOverflow)?;
        self.state = LinkState::Stopped;
        self.backoff.reset();
        self.lifecycle_events = self.lifecycle_events.saturating_add(1);
        Ok(self.generation)
    }

    pub fn account_traffic(
        &mut self,
        offered: u64,
        delivered: u64,
        queue_dropped: u64,
        quota_dropped: u64,
        malformed: u64,
    ) -> Result<(), Net3Error> {
        self.loss
            .account(offered, delivered, queue_dropped, quota_dropped, malformed)
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        StatusSnapshot {
            sequence: 0,
            generation: self.generation,
            state: self.state,
            retry_attempts: self.backoff.attempts(),
            last_retry_delay: self.backoff.last_delay(),
            next_retry_deadline: self.backoff.next_deadline(),
            loss: self.loss,
            lifecycle_events: self.lifecycle_events,
        }
    }

    pub fn observe(&mut self) -> bool {
        self.observations.publish(self.snapshot())
    }

    fn check_generation(&self, generation: u32) -> Result<(), Net3Error> {
        if generation == self.generation {
            Ok(())
        } else {
            Err(Net3Error::StaleGeneration)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> BackoffPolicy {
        BackoffPolicy {
            max_attempts: 3,
            initial_delay: 10,
            max_delay: 50,
            multiplier: 2,
        }
    }

    #[test]
    fn lifecycle_is_explicit_and_stale_generation_is_rejected() {
        let mut manager = NetworkManager::new(policy()).unwrap();
        assert_eq!(manager.state(), LinkState::Down);
        let generation = manager.start().unwrap();
        assert_eq!(manager.state(), LinkState::Probing);
        manager.probe_succeeded(generation).unwrap();
        assert_eq!(manager.state(), LinkState::Up);
        manager.link_lost(generation).unwrap();
        assert_eq!(manager.state(), LinkState::Degraded);
        manager.probe_succeeded(generation).unwrap();
        let stopped = manager.stop().unwrap();
        assert_eq!(manager.state(), LinkState::Stopped);
        assert_eq!(
            manager.probe_succeeded(generation),
            Err(Net3Error::StaleGeneration)
        );
        assert_eq!(stopped, generation + 1);
        assert_eq!(manager.observe(), true);
    }

    #[test]
    fn backoff_is_bounded_exhausts_and_resets() {
        let mut backoff = Backoff::new(policy()).unwrap();
        assert_eq!(
            backoff.schedule(100, 0),
            RetryDecision::Wait {
                attempt: 1,
                delay: 10,
                deadline: 110,
            }
        );
        assert!(matches!(
            backoff.schedule(0, u64::MAX),
            RetryDecision::Wait { attempt: 2, .. }
        ));
        assert!(matches!(
            backoff.schedule(0, u64::MAX),
            RetryDecision::Wait { attempt: 3, delay, .. } if delay <= 50
        ));
        assert_eq!(backoff.schedule(0, 0), RetryDecision::Exhausted);
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert!(matches!(
            backoff.schedule(0, 0),
            RetryDecision::Wait { attempt: 1, .. }
        ));
    }

    #[test]
    fn effective_loss_is_classified_and_traffic_mismatch_is_atomic() {
        let mut manager = NetworkManager::new(policy()).unwrap();
        manager.account_traffic(20, 12, 3, 2, 1).unwrap();
        let snapshot = manager.snapshot().loss;
        assert_eq!(snapshot.offered(), 20);
        assert_eq!(snapshot.delivered(), 12);
        assert_eq!(snapshot.transport_lost(), 2);
        assert_eq!(snapshot.queue_dropped(), 3);
        assert_eq!(snapshot.quota_dropped(), 2);
        assert_eq!(snapshot.malformed(), 1);
        assert_eq!(snapshot.total_lost(), 8);
        let before = manager.loss();
        assert_eq!(
            manager.account_traffic(1, 1, 1, 0, 0),
            Err(Net3Error::TrafficMismatch)
        );
        assert_eq!(manager.loss(), before);
    }

    #[test]
    fn observability_is_bounded_and_reports_dropped_snapshots() {
        let mut manager = NetworkManager::new(policy()).unwrap();
        for _ in 0..OBSERVATION_CAPACITY {
            assert!(manager.observe());
        }
        assert!(!manager.observe());
        assert_eq!(manager.observations().len(), OBSERVATION_CAPACITY);
        assert_eq!(manager.observations().dropped(), 1);
        let first = manager.observations_mut().pop().unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.state, LinkState::Down);

        let mut saturated = ObservationLog::new();
        saturated.next_sequence = u64::MAX;
        assert!(!saturated.publish(first));
        assert_eq!(saturated.dropped(), 1);
    }

    #[test]
    fn retry_failure_degrades_then_fails_and_fatal_probe_fails_immediately() {
        let mut manager = NetworkManager::new(policy()).unwrap();
        let generation = manager.start().unwrap();
        assert!(matches!(
            manager.probe_failed(generation, 0, 0, false).unwrap(),
            RetryDecision::Wait { attempt: 1, .. }
        ));
        assert_eq!(manager.state(), LinkState::Degraded);
        assert!(matches!(
            manager.probe_failed(generation, 10, 0, false).unwrap(),
            RetryDecision::Wait { attempt: 2, .. }
        ));
        assert!(matches!(
            manager.probe_failed(generation, 20, 0, false).unwrap(),
            RetryDecision::Wait { attempt: 3, .. }
        ));
        assert_eq!(
            manager.probe_failed(generation, 30, 0, false).unwrap(),
            RetryDecision::Exhausted
        );
        assert_eq!(manager.state(), LinkState::Failed);
        let restarted = manager.start().unwrap();
        assert_eq!(
            manager.probe_failed(restarted, 0, 0, true).unwrap(),
            RetryDecision::Exhausted
        );
        assert_eq!(manager.state(), LinkState::Failed);
    }
}
