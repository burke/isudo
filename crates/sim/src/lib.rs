//! Deterministic simulation of isudo.
//!
//! One process holds the real host logic (`isudo-core`), the real relay
//! state machine (`isudo-relay-core`) and the real phone logic
//! (`isudo-phone`). A seeded random schedule decides what happens next:
//! the host asks for something, the phone looks, the person approves or
//! denies, time passes, messages are lost. In adversarial runs an attacker
//! who controls the relay, the network and the unprivileged helper also
//! takes turns: replaying, relabelling, tampering and forging.
//!
//! After every step the simulator checks the properties the design exists
//! to provide:
//!
//! 1. A command runs only if the phone approved exactly that request, and
//!    what runs is what the phone displayed.
//! 2. No request runs twice.
//! 3. A denial reason reaches the caller only as the phone signed it.
//! 4. The phone displays only requests the host really made.
//!
//! In runs without faults it also checks the system is useful: everything
//! approved in time runs.
//!
//! A failure reports its seed; the same seed replays the same schedule.
//! (HPKE ciphertexts are randomized by the operating system, so their bytes
//! differ between replays. No decision in the simulation depends on them.)

#![forbid(unsafe_code)]

#[cfg(test)]
mod pairing_tests;
mod world;

pub use world::{run, Stats, Violation};

/// A small, fast, seedable generator (`SplitMix64`). Statistical quality is
/// irrelevant here; reproducibility is the point.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`, or 0 if `bound` is 0.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next().checked_rem(bound).unwrap_or(0)
    }

    /// True `percent` times in a hundred.
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0_u8; N];
        for chunk in out.chunks_mut(8) {
            for (dst, src) in chunk.iter_mut().zip(self.next().to_le_bytes()) {
                *dst = src;
            }
        }
        out
    }

    /// A random element, or None if the slice is empty.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        let index = usize::try_from(self.below(u64::try_from(items.len()).ok()?)).ok()?;
        items.get(index)
    }

    /// A random index into a collection of `len` items, or None if empty.
    pub fn index(&mut self, len: usize) -> Option<usize> {
        if len == 0 {
            return None;
        }
        usize::try_from(self.below(u64::try_from(len).ok()?)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeds per configuration in the ordinary test run. Set
    /// `ISUDO_SIM_SEEDS` to run more.
    fn seeds() -> u64 {
        std::env::var("ISUDO_SIM_SEEDS").ok().and_then(|n| n.parse().ok()).unwrap_or(40)
    }

    #[test]
    fn the_generator_is_reproducible() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        let first: Vec<u64> = (0..8).map(|_| a.next()).collect();
        assert_eq!(first, (0..8).map(|_| b.next()).collect::<Vec<_>>());
        assert_ne!(first, (0..8).map(|_| Rng::new(43).next()).collect::<Vec<_>>());
        assert_eq!(Rng::new(1).below(0), 0);
        assert_eq!(Rng::new(1).pick::<u8>(&[]), None);
    }

    #[test]
    fn without_faults_everything_approved_runs() {
        let (mut ran, mut ran_by_watch) = (0, 0);
        for seed in 0..seeds() {
            let stats = run(seed, 300, false).unwrap_or_else(|v| panic!("seed {seed}: {v}"));
            assert_eq!(stats.forged_verdicts, 0, "seed {seed}: nothing forges in a fault-free run");
            assert_eq!(stats.phone_refusals, 0, "seed {seed}: nothing is refused in a fault-free run");
            assert_eq!(stats.watch_refused, 0, "seed {seed}: an honest watch is never refused");
            ran += stats.executed;
            ran_by_watch += stats.watch_ran;
        }
        assert!(ran > 0, "the fault-free simulation never ran a command");
        assert!(ran_by_watch > 0, "nothing ever ran on the watch's approval");
        assert!(ran_by_watch < ran, "nothing ever ran on the phone's approval");
    }

    #[test]
    fn under_attack_nothing_unapproved_runs() {
        let mut totals = Stats::default();
        for seed in 0..seeds() {
            let stats = run(seed, 400, true).unwrap_or_else(|v| panic!("seed {seed}: {v}"));
            totals.executed += stats.executed;
            totals.forged_verdicts += stats.forged_verdicts;
            totals.phone_refusals += stats.phone_refusals;
            totals.attacks += stats.attacks;
            totals.watch_ran += stats.watch_ran;
            totals.watch_refused += stats.watch_refused;
            totals.watch_shown += stats.watch_shown;
        }
        // The run is only evidence if the attacker actually did things, the
        // defences actually fired, and legitimate work still got through.
        assert!(totals.attacks > 0, "no attacks were attempted");
        assert!(totals.forged_verdicts > 0, "no forgery was ever detected by the host");
        assert!(totals.phone_refusals > 0, "the phone never refused anything");
        assert!(totals.executed > 0, "nothing legitimate ran under attack");
        assert!(totals.watch_shown > 0, "the watch never showed anything");
        assert!(totals.watch_ran > 0, "nothing ran on a watch's approval under attack");
        assert!(totals.watch_refused > 0, "the host never had to refuse a watch");
    }
}
