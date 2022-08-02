
/// Docker inspect architecture constants
pub const DOCKER_ARCH_ARM64: &str = "arm64";
pub const DOCKER_ARCH_AMD64: &str = "amd64";

/// Root folder for the cache
// XDG_DATA_DIRS contains more directory paths, separated by ':', we will
// have to choose one based on some criteria
pub const CACHE_ROOT_FOLDER: &str = "XDG_DATA_DIRS";

/// The name of the actual image file from the image cache folder
pub const IMAGE_FILE_NAME: &str = "image_file";