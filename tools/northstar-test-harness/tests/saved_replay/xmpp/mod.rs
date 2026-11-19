//! The session's protocol tests and Stage 4 harnesses.

pub(crate) mod protocol;
#[cfg(test)]
pub(crate) mod stage4_auth_publication;
#[cfg(test)]
mod stage4_frame_capture;
#[cfg(test)]
pub(crate) mod stage4_native;
