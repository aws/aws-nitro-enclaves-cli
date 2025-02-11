#[derive(thiserror::Error, Debug)]
pub enum Error
{
	#[error(transparent)]
	ParseInt(#[from] std::num::ParseIntError),
	#[error(transparent)]
	TryFromInt(#[from] std::num::TryFromIntError),
	#[error(transparent)]
	Allocation(#[from] super::resources::Error),
	#[error("Invalid config file. This might happened due to old config file or config file corruption. See release notes :")]
	ConfigFileCorruption,
	#[error("WARNING! Requested resource pool is more than supported. Supported Enclave number is 4")]
	MoreResourcePoolThanSupported,
}
