use crate::VestingError;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    pub total_wei: U256,
    pub start_ts: u64,
    pub cliff_secs: u64,
    pub duration_secs: u64,
    pub released_wei: U256,
}
impl VestingSchedule {
    pub fn new(
        total_wei: U256,
        start_ts: u64,
        cliff_secs: u64,
        duration_secs: u64,
    ) -> Result<Self, VestingError> {
        let s = Self {
            total_wei,
            start_ts,
            cliff_secs,
            duration_secs,
            released_wei: U256::zero(),
        };
        s.validate()?;
        if total_wei.is_zero() {
            return Err(VestingError::InvalidTotal);
        }
        Ok(s)
    }
    pub fn new_unchecked(
        total_wei: U256,
        start_ts: u64,
        cliff_secs: u64,
        duration_secs: u64,
        released_wei: U256,
    ) -> Self {
        Self {
            total_wei,
            start_ts,
            cliff_secs,
            duration_secs,
            released_wei,
        }
    }
    pub fn vested_amount(&self, now_ts: u64) -> U256 {
        if now_ts < self.start_ts.saturating_add(self.cliff_secs) {
            return U256::zero();
        }
        if self.duration_secs == 0 || now_ts >= self.start_ts.saturating_add(self.duration_secs) {
            return self.total_wei;
        }
        let elapsed = now_ts.saturating_sub(self.start_ts);
        let duration = U256::from(self.duration_secs);
        let elapsed_u256 = U256::from(elapsed);
        if duration.is_zero() {
            return self.total_wei;
        }
        if let Some(product) = self.total_wei.checked_mul(elapsed_u256) {
            product / duration
        } else {
            (self.total_wei / duration).saturating_mul(elapsed_u256)
                + ((self.total_wei % duration).saturating_mul(elapsed_u256)) / duration
        }
    }
    pub fn locked_amount(&self, now_ts: u64) -> U256 {
        self.total_wei.saturating_sub(self.vested_amount(now_ts))
    }
    pub fn releasable_amount(&self, now_ts: u64) -> U256 {
        self.vested_amount(now_ts).saturating_sub(self.released_wei)
    }
    pub fn release(&mut self, now_ts: u64) -> Result<U256, VestingError> {
        self.validate()?;
        let amount = self.releasable_amount(now_ts);
        if amount.is_zero() {
            return Err(VestingError::NoTokensReleasable);
        }
        let next = self
            .released_wei
            .checked_add(amount)
            .ok_or(VestingError::ReleasedExceedsTotal)?;
        if next > self.total_wei {
            return Err(VestingError::ReleasedExceedsTotal);
        }
        self.released_wei = next;
        Ok(amount)
    }
    pub fn validate(&self) -> Result<(), VestingError> {
        if self.released_wei > self.total_wei {
            return Err(VestingError::ReleasedExceedsTotal);
        }
        if self.total_wei.is_zero() && self.released_wei.is_zero() {
            if self.duration_secs == 0 && self.cliff_secs == 0 {
                return Ok(());
            }
            if self.duration_secs > 0 || self.cliff_secs > 0 {
                return Err(VestingError::InvalidTotal);
            }
        }
        if self.duration_secs > 0 && self.cliff_secs > self.duration_secs {
            return Err(VestingError::CliffExceedsDuration);
        }
        if self.duration_secs == 0 && self.cliff_secs > 0 {
            let end = self.start_ts.saturating_add(self.cliff_secs);
            if end < self.start_ts {
                return Err(VestingError::InvalidSchedule);
            }
        }
        let vested_cap = self.total_wei;
        if self.released_wei > vested_cap {
            return Err(VestingError::ReleasedExceedsTotal);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vesting_schedule() {
        let mut schedule = VestingSchedule {
            total_wei: U256::from(1000),
            start_ts: 100,
            cliff_secs: 10,
            duration_secs: 100,
            released_wei: U256::zero(),
        };
        assert_eq!(schedule.vested_amount(99), U256::zero());
        assert_eq!(schedule.vested_amount(109), U256::zero());
        assert_eq!(schedule.vested_amount(110), U256::from(100));
        assert_eq!(schedule.vested_amount(150), U256::from(500));
        assert_eq!(schedule.vested_amount(200), U256::from(1000));
        assert_eq!(schedule.vested_amount(250), U256::from(1000));
        assert_eq!(schedule.locked_amount(150), U256::from(500));
        assert_eq!(schedule.releasable_amount(150), U256::from(500));
        let released = schedule.release(150).unwrap();
        assert_eq!(released, U256::from(500));
        assert_eq!(schedule.released_wei, U256::from(500));
        assert_eq!(schedule.releasable_amount(150), U256::zero());
        assert_eq!(schedule.releasable_amount(200), U256::from(500));
        let released2 = schedule.release(200).unwrap();
        assert_eq!(released2, U256::from(500));
        assert_eq!(schedule.released_wei, U256::from(1000));
        assert!(schedule.release(200).is_err());
    }
    #[test]
    fn test_zero_duration_vesting() {
        let schedule = VestingSchedule::new(U256::from(5000), 1000, 0, 0).expect("valid");
        assert_eq!(schedule.vested_amount(999), U256::zero());
        assert_eq!(schedule.vested_amount(1000), U256::from(5000));
    }
    #[test]
    fn test_new_rejects_invalid_params() {
        assert!(VestingSchedule::new(U256::zero(), 100, 0, 100).is_err());
        assert!(VestingSchedule::new(U256::from(1000), 100, 200, 100).is_err());
        assert!(VestingSchedule::new(U256::from(1000), 100, 10, 100).is_ok());
        let mut bad = VestingSchedule::new_unchecked(U256::from(100), 0, 0, 100, U256::from(200));
        assert_eq!(bad.validate(), Err(VestingError::ReleasedExceedsTotal));
        assert!(bad.release(200).is_err());
        bad.released_wei = U256::zero();
        bad.validate().expect("fixed");
    }
    #[test]
    fn test_overflow_safe_vesting_math() {
        let schedule = VestingSchedule::new_unchecked(U256::MAX, 0, 0, 100, U256::zero());
        let half = schedule.vested_amount(50);
        let full = schedule.vested_amount(100);
        assert_eq!(full, U256::MAX);
        assert!(half < full);
        assert!(half > U256::zero());
        let expected_half = U256::MAX / U256::from(100u64) * U256::from(50u64)
            + (U256::MAX % U256::from(100u64) * U256::from(50u64)) / U256::from(100u64);
        assert_eq!(half, expected_half);
    }
    #[test]
    fn test_release_is_fail_closed() {
        let mut s = VestingSchedule::new(U256::from(1000), 0, 0, 100).expect("valid");
        assert_eq!(s.release(0).unwrap_err(), VestingError::NoTokensReleasable);
        s.released_wei = U256::from(1000);
        assert!(s.release(100).is_err());
    }
}
