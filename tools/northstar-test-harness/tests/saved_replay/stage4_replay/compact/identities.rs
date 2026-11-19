use super::super::{IdentityIntroduction, IdentityLabel, Rejection, MAX_IDENTITIES};
use super::parser::Budget;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IdentityKey {
    Fixed(u128),
    Opaque(u8),
}
#[derive(Default)]
pub(super) struct Identities {
    first: BTreeMap<IdentityKey, usize>,
    pub(super) labels: Vec<IdentityLabel>,
}
impl Identities {
    fn key(label: &IdentityLabel, budget: &mut Budget) -> Result<IdentityKey, Rejection> {
        // Extra terminal inspection: object, kind, payload object, leaf. UUID
        // keys are integer values; ordered-map comparisons inspect no strings.
        budget.visits(4)?;
        Ok(match label {
            IdentityLabel::Fixed(v) => {
                budget.bytes(32)?;
                IdentityKey::Fixed(v.uuid.0.as_u128())
            }
            IdentityLabel::Opaque(v) => IdentityKey::Opaque(v.ordinal),
        })
    }
    pub(super) fn new(
        introductions: &[IdentityIntroduction],
        budget: &mut Budget,
    ) -> Result<Self, Rejection> {
        budget.visits(1)?;
        if introductions.len() > MAX_IDENTITIES {
            return Err(Rejection::Bound);
        }
        let mut result = Self::default();
        for (index, item) in introductions.iter().enumerate() {
            budget.visits(1)?;
            let key = Self::key(&item.label, budget)?;
            result.first.entry(key).or_insert(index);
            // A bounded typed terminal copy, never a shared expanded JSON node.
            budget.bytes(match key {
                IdentityKey::Fixed(_) => 16,
                IdentityKey::Opaque(_) => 1,
            })?;
            result.labels.push(item.label.clone());
        }
        Ok(result)
    }
    pub(super) fn index(
        &self,
        label: &IdentityLabel,
        budget: &mut Budget,
    ) -> Result<usize, Rejection> {
        let key = Self::key(label, budget)?;
        self.first.get(&key).copied().ok_or(Rejection::Encoding)
    }
}
