// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use super::{Fixed, Item, Numeric, Pad};

/// Iterator over the restricted strftime set documented at the crate root.
#[derive(Clone, Debug)]
pub struct StrftimeItems<'a> {
    remainder: &'a str,
    queue: &'static [Item<'static>],
    lenient: bool,
}
impl<'a> StrftimeItems<'a> {
    pub const fn new(s: &'a str) -> Self {
        Self {
            remainder: s,
            queue: &[],
            lenient: false,
        }
    }
}
impl<'a> Iterator for StrftimeItems<'a> {
    type Item = Item<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some((item, rest)) = self.queue.split_first() {
            self.queue = rest;
            return Some(item.clone());
        }
        let _ = self.lenient;
        let s = self.remainder;
        let first = s.chars().next()?;
        if first != '%' {
            let space = first.is_whitespace();
            let end = s
                .char_indices()
                .find(|(_, c)| *c == '%' || c.is_whitespace() != space)
                .map_or(s.len(), |(i, _)| i);
            self.remainder = &s[end..];
            return Some(if space {
                Item::Space(&s[..end])
            } else {
                Item::Literal(&s[..end])
            });
        }
        let tail = &s[1..];
        let c = match tail.chars().next() {
            Some(c) => c,
            None => {
                self.remainder = "";
                return Some(Item::Error);
            }
        };
        self.remainder = &tail[c.len_utf8()..];
        Some(match c {
            '%' => Item::Literal("%"),
            'Y' => Item::Numeric(Numeric::Year, Pad::Zero),
            'm' => Item::Numeric(Numeric::Month, Pad::Zero),
            'd' => Item::Numeric(Numeric::Day, Pad::Zero),
            'e' => Item::Numeric(Numeric::Day, Pad::Space),
            'b' => Item::Fixed(Fixed::ShortMonthName),
            'H' => Item::Numeric(Numeric::Hour, Pad::Zero),
            'M' => Item::Numeric(Numeric::Minute, Pad::Zero),
            'S' => Item::Numeric(Numeric::Second, Pad::Zero),
            'z' => Item::Fixed(Fixed::TimezoneOffset),
            '.' if self.remainder.starts_with('f') => {
                self.remainder = &self.remainder[1..];
                Item::Fixed(Fixed::Nanosecond)
            }
            '#' if self.remainder.starts_with('z') => {
                self.remainder = &self.remainder[1..];
                Item::Fixed(Fixed::Internal(super::InternalFixed {
                    val: super::InternalInternal::TimezoneOffsetPermissive,
                }))
            }
            _ => Item::Error,
        })
    }
}
