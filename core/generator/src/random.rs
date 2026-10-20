use crate::GeneratorError;

/// Generates an unbiased random index in the half-open range `0..upper_bound`.
///
/// Uses rejection sampling to completely eliminate modulo bias.
pub fn random_index(upper_bound: usize) -> Result<usize, GeneratorError> {
    if upper_bound <= 1 {
        return Ok(0);
    }

    if upper_bound <= u32::MAX as usize {
        let n = upper_bound as u32;
        // Standard rejection sampling algorithm:
        // Exclude the remainder zone at the top of the u32 range.
        let zone = (u32::MAX - (u32::MAX % n)).saturating_sub(1);
        loop {
            let mut buf = [0u8; 4];
            getrandom::getrandom(&mut buf)
                .map_err(|e| GeneratorError::EntropyFailed(e.to_string()))?;
            let val = u32::from_ne_bytes(buf);
            if val <= zone {
                return Ok((val % n) as usize);
            }
        }
    } else {
        let n = upper_bound as u64;
        let zone = (u64::MAX - (u64::MAX % n)).saturating_sub(1);
        loop {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf)
                .map_err(|e| GeneratorError::EntropyFailed(e.to_string()))?;
            let val = u64::from_ne_bytes(buf);
            if val <= zone {
                return Ok((val % n) as usize);
            }
        }
    }
}

/// Unbiased in-place Fisher-Yates shuffle.
pub fn shuffle<T>(slice: &mut [T]) -> Result<(), GeneratorError> {
    let len = slice.len();
    if len <= 1 {
        return Ok(());
    }

    for i in (1..len).rev() {
        let j = random_index(i + 1)?;
        slice.swap(i, j);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_index_bounds() {
        for bound in [2, 5, 10, 100, 1000] {
            for _ in 0..100 {
                let idx = random_index(bound).unwrap();
                assert!(idx < bound);
            }
        }
    }

    #[test]
    fn test_shuffle() {
        let mut items = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let original = items.clone();
        shuffle(&mut items).unwrap();
        // Permutation invariant
        let mut sorted = items.clone();
        sorted.sort();
        assert_eq!(sorted, original);
    }
}
