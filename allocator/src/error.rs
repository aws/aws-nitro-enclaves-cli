#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Allocation(#[from] super::resources::Error),
    #[error("Invalid or corrupted config file.")]
    ConfigFileCorruption,
    #[error(
        "WARNING! Requested resource pool is more than supported. Supported Enclave number is 4"
    )]
    MoreResourcePoolThanSupported,
}
