use std::fmt;

use openmls::prelude::WelcomeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ClientError {
    NoGroupStateAvailable,
    NoSuchInvite,
    InvalidInvite(#[from] WelcomeError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClientError::NoGroupStateAvailable => {
                write!(
                    f,
                    "Yet to receive shared group states to operate this group"
                )
            }
            ClientError::NoSuchInvite => {
                write!(f, "Cannot find an invite from this group locally")
            }
            ClientError::InvalidInvite(_) => {
                write!(
                    f,
                    "The latest welcome stored for this group locally is not usable"
                )
            }
        }
    }
}
