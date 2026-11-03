//! Users, sessions, devices, and organisation membership (domain, application, ports, adapters).

pub mod adapters;
pub mod application;
pub mod domain;
pub mod ports;

pub use application::{AuthService, AuthenticateError, DeviceFlowError, RegisterError};
pub use domain::{DeviceAuthId, DeviceId, EmailTokenId, SessionId, User, UserId};
pub use ports::{
    DeviceAuthRepository, DeviceRepository, EmailTokenRepository, SessionRepository, UserRepository,
};
