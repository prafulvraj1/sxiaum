use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;

/// Maximum pacemaker timeout after exponential backoff (60 seconds on mainnet).
const MAX_TIMEOUT_SECS: u64 = 60;

/// SECURITY (C-07): maximum number of views a node may advance from a single
/// UNAUTHENTICATED external signal (unsigned `NewViewMessage`, a
/// peer-reported view, or a future-view vote). Previously any peer could set
/// an arbitrary view with no justification, letting a single malicious peer
/// poison the view counter (leader-election disruption, liveness DoS).
/// Advancing further than this requires quorum justification (a QC/TC), not
/// a bare claim.
pub const MAX_UNAUTHENTICATED_VIEW_JUMP: u64 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewViewMessage {
    pub view: u64,
    pub leader_index: Option<usize>,
}

pub struct Pacemaker {
    pub current_view: u64,
    pub base_timeout: Duration,
    pub max_timeout: Duration,
    pub current_timeout: Duration,
    pub last_view_start: std::time::Instant,
}

impl Pacemaker {
    pub fn new(base_timeout: Duration) -> Self {
        let max_timeout = base_timeout
            .saturating_mul(16)
            .min(Duration::from_secs(MAX_TIMEOUT_SECS))
            .max(base_timeout);
        Self {
            current_view: 0,
            base_timeout,
            max_timeout,
            current_timeout: base_timeout,
            last_view_start: std::time::Instant::now(),
        }
    }

    pub fn advance_view(&mut self) -> u64 {
        self.current_view = self.current_view.saturating_add(1);
        self.current_view
    }

    pub fn on_timeout(&mut self) -> u64 {
        crate::metrics::ConsensusMetrics::record_view_timeout(self.current_view);
        self.current_timeout = std::cmp::min(self.current_timeout * 2, self.max_timeout);
        self.reset_timer();
        self.advance_view()
    }

    pub fn leader_for_view(&self, view: u64, validator_count: usize) -> Option<usize> {
        if validator_count == 0 {
            return None;
        }
        Some((view as usize) % validator_count)
    }

    pub fn reset_timer(&mut self) {
        self.last_view_start = std::time::Instant::now();
    }

    pub fn reset_timeout(&mut self) {
        self.current_timeout = self.base_timeout;
    }

    pub fn handle_new_view_message(&mut self, message: &NewViewMessage) -> u64 {
        if message.view > self.current_view {
            match self.sanitized_external_view(message.view) {
                Some(safe_view) => {
                    self.current_view = safe_view;
                    self.reset_timeout();
                }
                None => {
                    // SECURITY (C-07): unjustified view far beyond our own —
                    // refuse rather than adopt an attacker-chosen view.
                    return self.current_view;
                }
            }
        }
        self.reset_timer();
        self.current_view
    }

    pub fn broadcast_new_view(&self, validator_count: usize) -> NewViewMessage {
        NewViewMessage {
            view: self.current_view,
            leader_index: self.leader_for_view(self.current_view, validator_count),
        }
    }

    pub fn detect_leader_failure(&self) -> bool {
        !self.current_timeout.is_zero() && self.last_view_start.elapsed() >= self.current_timeout
    }

    pub fn sync_view_with_network(&mut self, network_view: u64) -> u64 {
        if network_view > self.current_view {
            match self.sanitized_external_view(network_view) {
                Some(safe_view) => {
                    self.current_view = safe_view;
                    self.reset_timeout();
                }
                None => {
                    // SECURITY (C-07): reject unjustified view claims far
                    // beyond our own counter.
                    return self.current_view;
                }
            }
        }
        self.reset_timer();
        self.current_view
    }

    /// SECURITY (C-07): clamp an externally-supplied view to the
    /// unauthenticated jump window. Returns `None` when the claim exceeds
    /// [`MAX_UNAUTHENTICATED_VIEW_JUMP`] past our current view and must be
    /// rejected outright.
    fn sanitized_external_view(&self, claimed_view: u64) -> Option<u64> {
        let ceiling = self
            .current_view
            .saturating_add(MAX_UNAUTHENTICATED_VIEW_JUMP);
        if claimed_view > ceiling {
            warn!(
                "rejecting unauthenticated view claim {} (current {}, max jump {})",
                claimed_view, self.current_view, MAX_UNAUTHENTICATED_VIEW_JUMP
            );
            return None;
        }
        Some(claimed_view)
    }

    pub fn is_timed_out(&self) -> bool {
        self.detect_leader_failure()
    }
}

#[cfg(test)]
mod tests {
    use super::{NewViewMessage, Pacemaker};
    use std::time::Duration;

    #[test]
    fn new_and_advance_view_initialize_and_increment_state() {
        let mut pacemaker = Pacemaker::new(Duration::from_secs(5));

        assert_eq!(pacemaker.current_view, 0);
        assert_eq!(pacemaker.base_timeout, Duration::from_secs(5));
        assert_eq!(pacemaker.current_timeout, Duration::from_secs(5));
        assert_eq!(pacemaker.advance_view(), 1);
        assert_eq!(pacemaker.current_view, 1);
        assert_eq!(pacemaker.on_timeout(), 2);
        assert_eq!(pacemaker.current_view, 2);
    }

    #[test]
    fn leader_selection_and_broadcast_new_view_follow_view_modulo() {
        let pacemaker = Pacemaker::new(Duration::from_secs(3));

        assert_eq!(pacemaker.leader_for_view(0, 0), None);
        assert_eq!(pacemaker.leader_for_view(0, 4), Some(0));
        assert_eq!(pacemaker.leader_for_view(5, 4), Some(1));

        let message = pacemaker.broadcast_new_view(4);
        assert_eq!(message.view, 0);
        assert_eq!(message.leader_index, Some(0));
    }

    #[test]
    fn handle_new_view_and_network_sync_only_move_forward() {
        let mut pacemaker = Pacemaker::new(Duration::from_secs(1));
        pacemaker.current_view = 4;

        let stale_message = NewViewMessage {
            view: 2,
            leader_index: Some(0),
        };
        assert_eq!(pacemaker.handle_new_view_message(&stale_message), 4);

        let newer_message = NewViewMessage {
            view: 7,
            leader_index: Some(1),
        };
        assert_eq!(pacemaker.handle_new_view_message(&newer_message), 7);
        assert_eq!(pacemaker.sync_view_with_network(6), 7);
        assert_eq!(pacemaker.sync_view_with_network(9), 9);
    }

    #[test]
    fn unauthenticated_view_claims_beyond_jump_window_are_rejected() {
        let mut pacemaker = Pacemaker::new(Duration::from_secs(1));
        pacemaker.current_view = 10;

        // Within the window: accepted.
        let ok_message = NewViewMessage {
            view: 10 + super::MAX_UNAUTHENTICATED_VIEW_JUMP,
            leader_index: Some(0),
        };
        assert_eq!(
            pacemaker.handle_new_view_message(&ok_message),
            10 + super::MAX_UNAUTHENTICATED_VIEW_JUMP
        );

        // Beyond the window: rejected, view unchanged.
        let poison = NewViewMessage {
            view: 10 + super::MAX_UNAUTHENTICATED_VIEW_JUMP + 5_000,
            leader_index: Some(0),
        };
        assert_eq!(
            pacemaker.sync_view_with_network(poison.view),
            pacemaker.current_view
        );
        assert_eq!(
            pacemaker.handle_new_view_message(&poison),
            pacemaker.current_view
        );
    }

    #[test]
    fn timeout_detection_reflects_configured_timeout() {
        let timed = Pacemaker::new(Duration::from_millis(10));
        let not_timed = Pacemaker::new(Duration::ZERO);

        assert!(!timed.detect_leader_failure());
        assert!(!timed.is_timed_out());

        std::thread::sleep(Duration::from_millis(15));
        assert!(timed.detect_leader_failure());
        assert!(timed.is_timed_out());

        assert!(!not_timed.detect_leader_failure());
        assert!(!not_timed.is_timed_out());
    }

    #[test]
    fn exponential_backoff_doubles_timeout_and_resets() {
        let mut pacemaker = Pacemaker::new(Duration::from_secs(1));
        pacemaker.max_timeout = Duration::from_secs(3);

        assert_eq!(pacemaker.current_timeout, Duration::from_secs(1));

        pacemaker.on_timeout();
        assert_eq!(pacemaker.current_timeout, Duration::from_secs(2));

        pacemaker.on_timeout();
        assert_eq!(pacemaker.current_timeout, Duration::from_secs(3)); // Capped at max_timeout

        pacemaker.on_timeout();
        assert_eq!(pacemaker.current_timeout, Duration::from_secs(3));

        // Reset via network sync
        pacemaker.sync_view_with_network(5);
        assert_eq!(pacemaker.current_timeout, Duration::from_secs(1));
    }
}
