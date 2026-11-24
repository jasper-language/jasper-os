//! Multi-source clock-provider selection for the time service layer.
//!
//! This module selects among evidence-bearing provider facts. It does not read
//! hardware, authenticate a protocol, estimate uncertainty, or convert an
//! untrusted source into trusted wall time.

use crate::clock_contract::{ClockQuality, Epoch, Measurement, SourceClass, TimeScale, TrustState};

pub const PROVIDER_CONTRACT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderHealth {
    Synchronized,
    Holdover,
    Unverified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderFacts {
    pub source: SourceClass,
    pub source_id: u64,
    pub generation: u64,
    pub scale: TimeScale,
    pub epoch: Epoch,
    pub trust: TrustState,
    pub synchronized: bool,
    pub resolution: Measurement,
    pub uncertainty: Measurement,
    pub sample_age: Measurement,
    pub holdover_limit: Measurement,
    pub priority: u16,
    pub quality: ClockQuality,
}

impl ProviderFacts {
    pub fn validate(self) -> Result<(), ProviderError> {
        if self.source == SourceClass::None
            || self.source_id == 0
            || self.generation == 0
            || self.quality.source != self.source
            || self.quality.source_id != self.source_id
            || self.quality.trust != self.trust
            || self.quality.synchronized != self.synchronized
            || self.quality.resolution != self.resolution
            || self.quality.uncertainty != self.uncertainty
            || self.quality.sample_age != self.sample_age
        {
            return Err(ProviderError::InvalidFacts);
        }
        if self
            .resolution
            .known_nanoseconds()
            .is_none_or(|value| value == 0)
        {
            return Err(ProviderError::UnknownResolution);
        }
        match (self.scale, self.epoch) {
            (
                TimeScale::RawMonotonic | TimeScale::Monotonic | TimeScale::Boottime,
                Epoch::Boot(_),
            ) => {}
            (TimeScale::Tai | TimeScale::Utc, Epoch::Unix) => {
                if !matches!(self.trust, TrustState::Authenticated | TrustState::Verified) {
                    return Err(ProviderError::InsufficientTrust);
                }
            }
            _ => return Err(ProviderError::InvalidFacts),
        }
        Ok(())
    }

    pub fn health(self) -> ProviderHealth {
        if self.synchronized {
            return ProviderHealth::Synchronized;
        }
        match (
            self.sample_age.known_nanoseconds(),
            self.holdover_limit.known_nanoseconds(),
        ) {
            (Some(age), Some(limit)) if age <= limit => ProviderHealth::Holdover,
            _ => ProviderHealth::Unverified,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionRequest {
    pub scale: TimeScale,
    pub epoch: Epoch,
    pub minimum_trust: TrustState,
    pub require_synchronized: bool,
    pub allow_holdover: bool,
    pub maximum_sample_age: Measurement,
    pub require_known_uncertainty: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub source: SourceClass,
    pub source_id: u64,
    pub generation: u64,
    pub health: ProviderHealth,
    pub trust: TrustState,
    pub quality: ClockQuality,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderError {
    InvalidFacts,
    UnknownResolution,
    InsufficientTrust,
    StaleGeneration,
    NoEligibleProvider,
    Capacity,
    UnknownProvider,
}

fn trust_rank(trust: TrustState) -> u8 {
    match trust {
        TrustState::Unknown => 0,
        TrustState::Untrusted => 1,
        TrustState::Authenticated => 2,
        TrustState::Verified => 3,
    }
}

fn health_rank(health: ProviderHealth) -> u8 {
    match health {
        ProviderHealth::Unverified => 0,
        ProviderHealth::Holdover => 1,
        ProviderHealth::Synchronized => 2,
    }
}

fn measured(value: Measurement) -> u64 {
    value.known_nanoseconds().unwrap_or(u64::MAX)
}

fn selection_of(facts: ProviderFacts) -> Selection {
    Selection {
        source: facts.source,
        source_id: facts.source_id,
        generation: facts.generation,
        health: facts.health(),
        trust: facts.trust,
        quality: facts.quality,
    }
}

fn better(candidate: &ProviderFacts, current: &ProviderFacts) -> bool {
    (
        trust_rank(candidate.trust),
        health_rank(candidate.health()),
        core::cmp::Reverse(measured(candidate.uncertainty)),
        core::cmp::Reverse(measured(candidate.resolution)),
        core::cmp::Reverse(measured(candidate.sample_age)),
        core::cmp::Reverse(candidate.priority),
        core::cmp::Reverse(candidate.source_id),
    ) > (
        trust_rank(current.trust),
        health_rank(current.health()),
        core::cmp::Reverse(measured(current.uncertainty)),
        core::cmp::Reverse(measured(current.resolution)),
        core::cmp::Reverse(measured(current.sample_age)),
        core::cmp::Reverse(current.priority),
        core::cmp::Reverse(current.source_id),
    )
}

pub fn select_provider<'a>(
    request: SelectionRequest,
    providers: impl IntoIterator<Item = &'a ProviderFacts>,
) -> Result<Selection, ProviderError> {
    let mut best: Option<ProviderFacts> = None;
    for &provider in providers {
        if provider.validate().is_err() {
            continue;
        }
        if provider.scale != request.scale || provider.epoch != request.epoch {
            continue;
        }
        if trust_rank(provider.trust) < trust_rank(request.minimum_trust) {
            continue;
        }
        let health = provider.health();
        if request.require_synchronized
            && health != ProviderHealth::Synchronized
            && !(request.allow_holdover && health == ProviderHealth::Holdover)
        {
            continue;
        }
        if let Some(maximum_age) = request.maximum_sample_age.known_nanoseconds() {
            match provider.sample_age.known_nanoseconds() {
                Some(age) if age <= maximum_age => {}
                _ => continue,
            }
        }
        if request.require_known_uncertainty && provider.uncertainty.known_nanoseconds().is_none() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current| better(&provider, current))
        {
            best = Some(provider);
        }
    }
    best.map(selection_of)
        .ok_or(ProviderError::NoEligibleProvider)
}

/// Bounded provider set with generation-safe replacement and revocation.
pub struct ProviderSet<const N: usize> {
    providers: [Option<ProviderFacts>; N],
}

impl<const N: usize> ProviderSet<N> {
    pub const fn new() -> Self {
        Self {
            providers: [None; N],
        }
    }

    pub fn register(&mut self, facts: ProviderFacts) -> Result<(), ProviderError> {
        facts.validate()?;
        if let Some(existing) = self.providers.iter().flatten().find(|existing| {
            existing.source == facts.source && existing.source_id == facts.source_id
        }) {
            if facts.generation <= existing.generation {
                return Err(ProviderError::StaleGeneration);
            }
        }
        let slot = self
            .providers
            .iter()
            .position(|existing| {
                existing.is_some_and(|existing| {
                    existing.source == facts.source && existing.source_id == facts.source_id
                })
            })
            .or_else(|| self.providers.iter().position(Option::is_none))
            .ok_or(ProviderError::Capacity)?;
        self.providers[slot] = Some(facts);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        source: SourceClass,
        source_id: u64,
        generation: u64,
    ) -> Result<(), ProviderError> {
        let slot = self
            .providers
            .iter()
            .position(|provider| {
                provider.is_some_and(|provider| {
                    provider.source == source
                        && provider.source_id == source_id
                        && provider.generation == generation
                })
            })
            .ok_or(ProviderError::UnknownProvider)?;
        self.providers[slot] = None;
        Ok(())
    }

    pub fn select(&self, request: SelectionRequest) -> Result<Selection, ProviderError> {
        select_provider(request, self.providers.iter().flatten())
    }

    pub fn len(&self) -> usize {
        self.providers.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<const N: usize> Default for ProviderSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(
        source: SourceClass,
        source_id: u64,
        trust: TrustState,
        synchronized: bool,
        uncertainty: u64,
        resolution: u64,
        age: u64,
    ) -> ProviderFacts {
        let quality = ClockQuality {
            source,
            source_id,
            trust,
            synchronized,
            resolution: Measurement::Nanoseconds(resolution),
            uncertainty: Measurement::Nanoseconds(uncertainty),
            sample_age: Measurement::Nanoseconds(age),
            drift_ppb: None,
        };
        ProviderFacts {
            source,
            source_id,
            generation: 1,
            scale: TimeScale::Utc,
            epoch: Epoch::Unix,
            trust,
            synchronized,
            resolution: quality.resolution,
            uncertainty: quality.uncertainty,
            sample_age: quality.sample_age,
            holdover_limit: Measurement::Nanoseconds(1_000_000),
            priority: 10,
            quality,
        }
    }

    fn utc_request() -> SelectionRequest {
        SelectionRequest {
            scale: TimeScale::Utc,
            epoch: Epoch::Unix,
            minimum_trust: TrustState::Authenticated,
            require_synchronized: true,
            allow_holdover: false,
            maximum_sample_age: Measurement::Nanoseconds(2_000_000),
            require_known_uncertainty: true,
        }
    }

    #[test]
    fn selects_best_authenticated_synchronized_source() {
        let ntp = provider(
            SourceClass::Ntp,
            1,
            TrustState::Authenticated,
            true,
            500,
            100,
            100,
        );
        let ptp = provider(
            SourceClass::Ptp,
            2,
            TrustState::Authenticated,
            true,
            50,
            10,
            200,
        );
        let untrusted = provider(SourceClass::Rtc, 3, TrustState::Untrusted, true, 0, 1, 0);
        let selected = select_provider(utc_request(), [&ntp, &ptp, &untrusted]).unwrap();
        assert_eq!(selected.source, SourceClass::Ptp);
        assert_eq!(selected.source_id, 2);
        assert_eq!(selected.health, ProviderHealth::Synchronized);
    }

    #[test]
    fn stale_unknown_and_unsynchronized_sources_fail_closed() {
        let stale = provider(
            SourceClass::Ntp,
            1,
            TrustState::Verified,
            true,
            1,
            1,
            3_000_000,
        );
        let unknown = provider(
            SourceClass::Ntp,
            2,
            TrustState::Authenticated,
            true,
            1,
            1,
            1,
        );
        let mut unknown = unknown;
        unknown.uncertainty = Measurement::Unknown;
        unknown.quality.uncertainty = Measurement::Unknown;
        let holdover = provider(
            SourceClass::Ntp,
            3,
            TrustState::Authenticated,
            false,
            1,
            1,
            100,
        );
        assert_eq!(
            select_provider(utc_request(), [&stale, &unknown, &holdover]),
            Err(ProviderError::NoEligibleProvider)
        );
    }

    #[test]
    fn holdover_requires_explicit_permission_and_fresh_age() {
        let holdover = provider(
            SourceClass::Ntp,
            1,
            TrustState::Authenticated,
            false,
            500,
            100,
            500_000,
        );
        assert_eq!(holdover.health(), ProviderHealth::Holdover);
        assert_eq!(
            select_provider(utc_request(), [&holdover]),
            Err(ProviderError::NoEligibleProvider)
        );
        let request = SelectionRequest {
            allow_holdover: true,
            ..utc_request()
        };
        assert_eq!(
            select_provider(request, [&holdover]).unwrap().health,
            ProviderHealth::Holdover
        );
    }

    #[test]
    fn provider_generations_cannot_resurrect_old_state() {
        let first = provider(SourceClass::Ptp, 7, TrustState::Verified, true, 10, 1, 0);
        let mut second = first;
        second.generation = 2;
        let mut set = ProviderSet::<4>::new();
        set.register(first).unwrap();
        set.register(second).unwrap();
        assert_eq!(set.register(first), Err(ProviderError::StaleGeneration));
        assert_eq!(
            set.revoke(SourceClass::Ptp, 7, 1),
            Err(ProviderError::UnknownProvider)
        );
        set.revoke(SourceClass::Ptp, 7, 2).unwrap();
        assert!(set.is_empty());
    }
}
