use lazy_static::lazy_static;

use std::collections::HashMap;

use crate::common::{NitroCliErrorEnum, NitroCliFailure};

lazy_static! {
    /// Structure mapping enum Errors to a specific error code.
    pub static ref ERROR_CODES: HashMap<NitroCliErrorEnum, &'static str> =
        [
            (NitroCliErrorEnum::UnspecifiedError, "E00"),
            (NitroCliErrorEnum::MissingArgument, "E01"),
            (NitroCliErrorEnum::ConflictingArgument, "E02"),
            (NitroCliErrorEnum::InvalidArgument, "E03"),
            (NitroCliErrorEnum::SocketPairCreationFailure, "E04"),
            (NitroCliErrorEnum::ProcessSpawnFailure, "E05"),
            (NitroCliErrorEnum::DaemonizeProcessFailure, "E06"),
            (NitroCliErrorEnum::ReadFromDiskFailure, "E07"),
            (NitroCliErrorEnum::UnusableConnectionError, "E08"),
            (NitroCliErrorEnum::SocketCloseError, "E09"),
            (NitroCliErrorEnum::SocketConnectTimeoutError, "E10"),
            (NitroCliErrorEnum::SocketError, "E11"),
            (NitroCliErrorEnum::EpollError, "E12"),
            (NitroCliErrorEnum::InotifyError, "E13"),
            (NitroCliErrorEnum::InvalidCommand, "E14"),
            (NitroCliErrorEnum::LockAcquireFailure, "E15"),
            (NitroCliErrorEnum::ThreadJoinFailure, "E16"),
            (NitroCliErrorEnum::SerdeError, "E17"),
            (NitroCliErrorEnum::FilePermissionsError, "E18"),
            (NitroCliErrorEnum::FileOperationFailure, "E19"),
            (NitroCliErrorEnum::InvalidCpuConfiguration, "E20"),
            (NitroCliErrorEnum::NoSuchCpuAvailableInPool, "E21"),
            (NitroCliErrorEnum::InsufficientCpus, "E22"),
            (NitroCliErrorEnum::MalformedCpuId, "E23"),
            (NitroCliErrorEnum::CpuError, "E24"),
            (NitroCliErrorEnum::NoSuchHugepageFlag, "E25"),
            (NitroCliErrorEnum::InsufficientMemoryRequested, "E26"),
            (NitroCliErrorEnum::InsufficientMemoryAvailable, "E27"),
            (NitroCliErrorEnum::InvalidEnclaveFd, "E28"),
            (NitroCliErrorEnum::IoctlFailure, "E29"),
            (NitroCliErrorEnum::IoctlImageLoadInfoFailure, "E30"),
            (NitroCliErrorEnum::IoctlSetMemoryRegionFailure, "E31"),
            (NitroCliErrorEnum::IoctlAddVcpuFailure, "E32"),
            (NitroCliErrorEnum::IoctlEnclaveStartFailure, "E33"),
            (NitroCliErrorEnum::MemoryOverflow, "E34"),
            (NitroCliErrorEnum::EifParsingError, "E35"),
            (NitroCliErrorEnum::EnclaveBootFailure, "E36"),
            (NitroCliErrorEnum::EnclaveEventWaitError, "E37"),
            (NitroCliErrorEnum::EnclaveProcessCommandNotExecuted, "E38"),
            (NitroCliErrorEnum::EnclaveProcessConnectionFailure, "E39"),
            (NitroCliErrorEnum::SocketPathNotFound, "E40"),
            (NitroCliErrorEnum::EnclaveProcessSendReplyFailure, "E41"),
            (NitroCliErrorEnum::EnclaveMmapError, "E42"),
            (NitroCliErrorEnum::EnclaveMunmapError, "E43"),
            (NitroCliErrorEnum::EnclaveConsoleConnectionFailure, "E44"),
            (NitroCliErrorEnum::EnclaveConsoleReadError, "E45"),
            (NitroCliErrorEnum::EnclaveConsoleWriteOutputError, "E46"),
            (NitroCliErrorEnum::IntegerParsingError, "E47"),
            (NitroCliErrorEnum::EifBuildingError, "E48"),
            (NitroCliErrorEnum::DockerImageBuildError, "E49"),
            (NitroCliErrorEnum::DockerImagePullError, "E50"),
            (NitroCliErrorEnum::ArtifactsPathNotSet, "E51"),
            (NitroCliErrorEnum::BlobsPathNotSet, "E52"),
            (NitroCliErrorEnum::ClockSkewError, "E53"),
            (NitroCliErrorEnum::SignalMaskingError, "E54"),
            (NitroCliErrorEnum::SignalUnmaskingError, "E55"),
            (NitroCliErrorEnum::LoggerError, "E56"),
            (NitroCliErrorEnum::HasherError, "E57"),
            (NitroCliErrorEnum::EnclaveNamingError, "E58"),
            (NitroCliErrorEnum::EIFSignatureCheckerError, "E59"),
        ].iter().cloned().collect();
}

/// Returns detailed error information based on supplied arguments.
pub fn get_detailed_info(error_code_str: String, additional_info: &[String]) -> String {
    let mut ret = format!("[ {} ] ", error_code_str);
    let info_placeholder = "MISSING_INFO".to_string();

    match error_code_str.as_str() {
        "E00" => {
            ret.push_str("Unspecified error. This is used as a catch-all error and should not be used in the code.");
        }
        "E01" => {
            ret.push_str(
                format!(
                    "Missing mandatory argument. User did not provide the `{}` argument.",
                    additional_info.get(0).unwrap_or(&info_placeholder)
                )
                .as_str(),
            );
        }
        "E02" => {
            ret.push_str(
                format!(
                    "Conflicting arguments. User provided both `{}` and `{}`.",
                    additional_info.get(0).unwrap_or(&info_placeholder),
                    additional_info.get(1).unwrap_or(&info_placeholder)
                )
                .as_str(),
            );
        }
        "E03" => {
            ret.push_str(
                format!(
                    "Invalid argument provided. The parameter `{}` is not a valid integer (`{}`)",
                    additional_info.get(0).unwrap_or(&info_placeholder),
                    additional_info.get(1).unwrap_or(&info_placeholder)
                )
                .as_str(),
            );
        }
        "E04" => {
            ret.push_str("Socket pair creation failure. Such error appears when the Nitro CLI process attempts to open a stream pair in order to send a command to the enclave process but the stream initialization fails.");
        }
        "E05" => {
            ret.push_str("Process spawn failure. Such error appears when the main Nitro CLI process fails to spawn the enclave process, in order to complete a `run-enclave` command.");
        }
        "E06" => {
            ret.push_str("Daemonize process failure. Such error appears when the system fails to daemonize a newly spawned enclave process.");
        }
        "E07" => {
            ret.push_str("Read from disk failure. Such error appears when the Nitro CLI process fails to read the content of the enclave sockets directory (usually '/run/nitro_enclaves/') in order to perform a `describe-enclave` operation. Check that the directory exists and it has proper permissions, or run the Nitro Enclaves configuration script in order to (re)configure the environment.");
        }
        "E08" => {
            ret.push_str("Unusable connection error. Such error appears when the Nitro CLI process attempts to open a connection to a non-existing or previously closed enclave descriptor");
        }
        "E09" => {
            ret.push_str("Socket close error. Such error appears when the system fails to successfully close a communication channel.");
        }
        "E10" => {
            ret.push_str("Socket connect set timeout error. Such error appears when the system fails to configure a specific timeout for a given socket. May arise when trying to connect to an enclave's console.");
        }
        "E11" => {
            ret.push_str("Socket error. This is used as an error for catching any other socket operation errors not covered by previous custom errors.");
        }
        "E12" => {
            ret.push_str("Epoll error. Such error appears, for instance, when the system fails to register a specific enclave descriptor with epoll in order to monitor events for it.");
        }
        "E13" => {
            ret.push_str("Inotify error. Such error appears when the system fails to configure a socket for monitorization.");
        }
        "E14" => {
            ret.push_str("Invalid command. Such error appears when an unknown command and / or unknown arguments are sent through a socket.");
        }
        "E15" => {
            ret.push_str("Lock acquire failure. Such error appears when the system fails to obtain the lock for an object with concurrent access, such as a structure containing information about a running enclave.");
        }
        "E16" => {
            ret.push_str("Thread join failure. Such error appears when the system fails to successfully join a thread, after it finished executing.");
        }
        "E17" => {
            ret.push_str("Serde error. Such error appears when serializing / deserializing a command or response fails.");
        }
        "E18" => {
            ret.push_str("File permissions error. Such error appears when a user other than the owner of the logging file (usually '/var/log/nitro_enclaves/nitro_enclaves.log') attempts to change the file permissions");
        }
        "E19" => {
            ret.push_str("File operation failure. Such error appears when the system fails to perform the requested file operations, such as opening the EIF file when launching an enclave, or seeking to a specific offset in the EIF file, or writing to the log file.");
            if additional_info.len() >= 2 {
                ret.push_str(
                    format!(
                        "\nFile: '{}', failing operation: '{}'.",
                        additional_info.get(0).unwrap_or(&info_placeholder),
                        additional_info.get(1).unwrap_or(&info_placeholder),
                    )
                    .as_str(),
                );
            }
        }
        "E20" => {
            ret.push_str(
                format!(
                    "Invalid CPU configuration. User provided `{}` contains same CPU(s) (CPU(s) {}) multiple times.",
                    additional_info.get(0).unwrap_or(&info_placeholder),
                    additional_info.get(1).unwrap_or(&info_placeholder),
                )
                .as_str(),
            );
        }
        "E21" => {
            ret.push_str(
                format!(
                    "No such CPU available in the pool. User provided `{}` contains CPU {}, which is not available in the pool.\nYou can add a specific CPU to the CPU pool by editing the `cpu_pool` value from '/etc/nitro_enclaves/allocator.yaml' and then enable the nitro-enclaves-allocator.service.",
                    additional_info.get(0).unwrap_or(&info_placeholder),
                    additional_info.get(1).unwrap_or(&info_placeholder),
                ).as_str(),
            );
        }
        "E22" => {
            ret.push_str(
                format!(
                    "Insufficient CPUs available in the pool. User provided `{}` is {}, which is more than the configured CPU pool size.\nYou can increase the CPU pool size by editing the `cpu_count` value from '/etc/nitro_enclaves/allocator.yaml' and then enable the nitro-enclaves-allocator.service.",
                    additional_info.get(0).unwrap_or(&info_placeholder),
                    additional_info.get(1).unwrap_or(&info_placeholder),
                ).as_str(),
            );
        }
        "E23" => {
            ret.push_str("Malformed CPU ID error. Such error appears when a `lscpu` line is malformed and reports an invalid online CPUs list.");
        }
        "E24" => {
            ret.push_str("CPU error. Such error appears when a CPU line interval is invalid (for instance, 0-3-7)");
        }
        "E25" => {
            ret.push_str("No such hugepage flag error. Such error appears when the enclave process attempts to use an invalid hugepage size (size other than the known hugepage sizes) for initializing the enclave memory.");
        }
        "E26" => {
            if additional_info.len() >= 3 {
                ret.push_str(
                    format!(
                        "Insufficient memory requested. User provided `{}` is {} MB, but based on the EIF file size, the minimum memory should be {} MB",
                        additional_info.get(0).unwrap_or(&info_placeholder),
                        additional_info.get(1).unwrap_or(&info_placeholder),
                        additional_info.get(2).unwrap_or(&info_placeholder)
                    ).as_str(),
                );
            } else {
                ret.push_str(
                    format!(
                        "Insufficient memory requested. User provided `{}` is {} MB, and memory should be greater than 0 MB.",
                        additional_info.get(0).unwrap_or(&info_placeholder),
                        additional_info.get(1).unwrap_or(&info_placeholder)
                    ).as_str(),
                );
            }
        }
        "E27" => {
            ret.push_str(
                format!(
                    "Insufficient memory available. User provided `{}` is {} MB, which is more than the available hugepage memory.\nYou can increase the available memory by editing the `memory_mib` value from '/etc/nitro_enclaves/allocator.yaml' and then restart the nitro-enclaves-allocator.service.",
                    additional_info.get(0).unwrap_or(&info_placeholder),
                    additional_info.get(1).unwrap_or(&info_placeholder)
                ).as_str(),
            );
        }
        "E28" => {
            ret.push_str("Invalid enclave descriptor. Such error appears when the NE_CREATE_VM ioctl returns with an error.");
        }
        "E29" => {
            ret.push_str("Ioctl failure. Such error is used as a general ioctl error and appears whenever an ioctl fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E30" => {
            ret.push_str("Ioctl image get load info failure. Such error appears when the ioctl used for getting the memory load information fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E31" => {
            ret.push_str("Ioctl set memory region failure. Such error appears when the ioctl used for setting a given memory region fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E32" => {
            ret.push_str("Ioctl add vCPU failure. Such error appears when the ioctl used for adding a vCPU fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E33" => {
            ret.push_str("Ioctl start enclave failure. Such error appears when the ioctl used for starting an enclave fails. In this case, the error backtrace provides details information on what specifically failed during the ioctl.");
        }
        "E34" => {
            ret.push_str("Memory overflow. Such error may appear during loading the EIF in the memory regions which will be conceded to the future enclave, if the regions offset plus the EIF file size exceeds the maximum address of the target platform.");
        }
        "E35" => {
            ret.push_str("EIF file parsing error. Such errors appear when attempting to fill a memory region with a section of the EIF file, but reading the entire section fails. This might indicate that the required hugepages are not available.");
        }
        "E36" => {
            ret.push_str("Enclave boot failure. Such error appears when attempting to receive the `ready` signal from a freshly booted enclave. It arises in several contexts, for instance, when the enclave is booted from an invalid EIF file and the enclave process immediately exits, failing to submit the `ready` signal. In this case, the error backtrace provides detailed information on what specifically failed during the enclave boot process.");
        }
        "E37" => {
            ret.push_str("Enclave event wait error. Such error appears when monitoring an enclave descriptor for events fails.");
        }
        "E38" => {
            ret.push_str("Enclave process command not executed error. Such error appears when at least one enclave fails to provide the description information.");
        }
        "E39" => {
            ret.push_str("Enclave process connection failure. Such error appears when the enclave manager fails to connect to at least one enclave process for retrieving the description information.");
        }
        "E40" => {
            ret.push_str("Socket path not found. Such error appears when the Nitro CLI process fails to build the corresponding socket path starting from a given enclave ID.");
        }
        "E41" => {
            ret.push_str("Enclave process send reply failure. Such error appears when the enclave process fails to submit the status code to the Nitro CLI process after performing a run / describe / terminate command.");
        }
        "E42" => {
            ret.push_str(
                "Enclave mmap error. Such error appears when allocating the enclave memory fails.",
            );
        }
        "E43" => {
            ret.push_str(
                "Enclave munmap error. Such error appears when unmapping the enclave memory fails.",
            );
        }
        "E44" => {
            ret.push_str("Enclave console connection failure. Such error appears when the Nitro CLI process fails to establish a connection to a running enclave's console.");
        }
        "E45" => {
            ret.push_str("Enclave console read error. Such error appears when reading from a running enclave's console fails.");
        }
        "E46" => {
            ret.push_str("Enclave console write output error. Such error appears when writing the information retrieved from a running enclave's console (to a given stream) fails.");
        }
        "E47" => {
            ret.push_str("Integer parsing error. Such error appears when trying to connect to a running enclave's console, but the enclave CID cannot be parsed correctly.");
        }
        "E48" => {
            ret.push_str("EIF building error. Such error appears when trying to build an EIF file. In this case, the error backtrace provides detailed information on the failure reason.");
        }
        "E49" => {
            ret.push_str("Docker image build error. Such error appears when trying to build and EIF file, but building the corresponding docker image fails. In this case, the error backtrace provides detailed information on the failure reason.");
        }
        "E50" => {
            ret.push_str("Docker image pull error. Such error appears when trying to build an EIF file, but pulling the corresponding docker image fails. In this case, the error backtrace provides detailed informatino on the failure reason.");
        }
        "E51" => {
            ret.push_str("Artifacts path environment variable not set. Such error appears when trying to build an EIF file, but the artifacts path environment variable is not set.");
        }
        "E52" => {
            ret.push_str("Blobs path environment variable not set. Such error appears when trying to build an EIF file, but the blobs path environment variable is not set.");
        }
        "E53" => {
            ret.push_str("Clock skew error. Such error appears when continuously reading from a running enclave's console, but measuring the time elapsed between consecutive reads failed.");
        }
        "E54" => {
            ret.push_str("Signal masking error. Such error appears if attempting to mask specific signals before creating an enclave process fails.");
        }
        "E55" => {
            ret.push_str("Signal unmasking error. Such error appears if attempting to unmask specific signals after creating an enclave process fails.");
        }
        "E56" => {
            ret.push_str("Logger error. Such error appears when attempting to initialize the underlying logging system fails.");
        }
        "E57" => {
            ret.push_str("Hasher error. Such error appears when trying to initialize a hasher or write bytes to it, resulting in a IO error.");
        }
        "E58" => {
            ret.push_str("Naming error. Such error appears when trying to perform an enclave operation using the enclave name and the name is invalid.");
        }
        "E59" => {
            ret.push_str("EIF signature checker error. Such error appears when validation of the signing certificate fails.");
        }
        _ => {
            ret.push_str(format!("No such error code {}", error_code_str).as_str());
        }
    }

    ret
}

/// Returns a link with more detailed information regarding a specific error.
pub fn construct_help_link(error_code_str: String) -> String {
    format!(
        "https://docs.aws.amazon.com/enclaves/latest/user/cli-errors.html#{}",
        error_code_str
    )
}

/// Returns a string containing the backtrace recorded during propagating an error message
pub fn construct_backtrace(failure_info: &NitroCliFailure) -> String {
    let version = env!("CARGO_PKG_VERSION").to_string();

    format!("  Action: {}\n  Subactions:{}\n  Root error file: {}\n  Root error line: {}\n  Version: {}",
        failure_info.action,
        failure_info.subactions.iter().rev().fold("".to_string(), |acc, x| {
            format!("{}\n    {}", acc, x)
        }),
        failure_info.file,
        failure_info.line,
        version)
}

/// Detailed information based on user-provided error code.
pub fn explain_error(error_code_str: String) {
    match error_code_str.as_str() {
        "E00" => {
            eprintln!("Unspecified error. This is used as a catch-all error and should not be used in the code.");
        }
        "E01" => {
            eprintln!("Missing mandatory argument. Such error appears when the Nitro CLI is requested to perform an operation, but not all of the mandatory arguments were supplied.\n\tExample: `nitro-cli run-enclave --cpu-count 2 --eif-path /path/to/my/eif`. Note that in this case, the mandatory parameter `--memory` is missing a value.");
        }
        "E02" => {
            eprintln!("CLI conflicting arguments. Such error appears when the Nitro CLI is supplied two contradicting arguments at the same time, such as `--cpu-count` and `--cpu-ids`.\nIn this case, only one of the parameters should be supplied.");
        }
        "E03" => {
            eprintln!("Invalid argument provided. Such error appears when the type of at least one of the arguments provided to the Nitro CLI does not match the expected type of that parameter.\n\tExample: `nitro-cli run-enclave --cpu-count 1z --memory 80 --eif-path /path/to/my/eif`. In this case, `cpu-count` is not a valid integer value." );
        }
        "E04" => {
            eprintln!("Socket pair creation failure. Such error apears when the Nitro CLI process attempts to open a stream pair in order to send a command to the enclave process, but the stream initialization fails.");
        }
        "E05" => {
            eprintln!("Process spawn failure. Such error appears when the main Nitro CLI process failed to spawn the enclave process, in order to complete a `run-enclave` command.");
        }
        "E06" => {
            eprintln!("Daemonize process failure. Such error appears when the system fails to daemonize the newly spawned enclave process.")
        }
        "E07" => {
            eprintln!("Read from disk failure. Such error appears when the Nitro CLI process fails to read the content of the enclave sockets directory (usually '/run/nitro_enclaves/') in order to perform a `describe-enclave` operation. Check that the directory exists and it has proper permissions, or run the Nitro Enclaves configuration script in order to (re)configure the environment.");
        }
        "E08" => {
            eprintln!("Unusable connection error. Such error appears when the Nitro CLI process attempts to open a connection to a non-existing or previously closed enclave descriptor");
        }
        "E09" => {
            eprintln!("Socket close error. Such error appears when the system fails to successfully close a communication channel.");
        }
        "E10" => {
            eprintln!("Socket connect set timeout error. Such error appears when the system fails to configure a specific timeout for a given socket. May arise when trying to connect to an enclave's console.");
        }
        "E11" => {
            eprintln!("Socket error. This is used as an error for catching any other socket operation errors not covered by previous custom errors.");
        }
        "E12" => {
            eprintln!("Epoll error. Such error appears, for instance, when the system fails to register a specific enclave descriptor with epoll in order to monitor events for it.");
        }
        "E13" => {
            eprintln!("Inotify error. Such error appears when the system fails to configure a socket for monitorization.");
        }
        "E14" => {
            eprintln!("Invalid command. Such error appears when an unknown command and / or unknown arguments are sent through a socket.");
        }
        "E15" => {
            eprintln!("Lock acquire failure. Such error appears when the system fails to obtain the lock for an object with concurrent access, such as a structure containing information about a running enclave.");
        }
        "E16" => {
            eprintln!("Thread join failure. Such error appears when the system fails to successfully join a thread, after it finished executing.");
        }
        "E17" => {
            eprintln!("Serde error. Such error appears when serializing / deserializing a command or response fails.");
        }
        "E18" => {
            eprintln!("File permissions error. Such error appears when a user other than the owner of the logging file (usually '/var/log/nitro_enclaves/nitro_enclaves.log') attempts to change the file permissions");
        }
        "E19" => {
            eprintln!("File operation failure. Such error appears when the system fails to perform the requested file operations, such as opening the EIF file when launching an enclave, or seeking to a specific offset in the EIF file, or writing to the log file.");
        }
        "E20" => {
            eprintln!("Invalid CPU configuration. Such error appears when the user supplies the same CPU ID multiple times.\n\tExample: `nitro-cli run-enclave --cpu-ids 1 1 --memory 80 --eif-path /path/to/my/eif`. In this case, CPU ID `1` has been selected twice.");
        }
        "E21" => {
            eprintln!("No such CPU available in the pool. Such error appears when the user requests to run an enclave with at least one CPU ID which does not exist in the CPU pool.\n\tExample: (configured CPU pool: [1,9]) `nitro-cli run-enclave --cpu-ids 1 2 --memory 80 --eif-path /path/to/my/eif`. In this case, CPU 2 is not in the configured CPU pool.");
        }
        "E22" => {
            eprintln!("Insufficient CPUs available in the pool. Such error appears when the user requests to run an enclave with more CPUs that available in the CPU pool.\n\tExample: (configured CPU pool: [1,9]) `nitro-cli run-enclave --cpu-count 4 --memory 80 --eif-path /path/to/my/eif`. In this case, the user requested 4 CPUs, but the CPU pool contains only 2.");
        }
        "E23" => {
            eprintln!("Malformed CPU ID error. Such error appears when a `lscpu` line is malformed and reports an invalid online CPUs list.");
        }
        "E24" => {
            eprintln!(
                "CPU error. Such error appears when a CPU line interval is invalid (as in 0-3-7)"
            );
        }
        "E25" => {
            eprintln!("No such hugepage flag error. Such error appears when the enclave process attempts to use an invalid hugepage size (size other than the known hugepage sizes) for initializing the enclave memory.");
        }
        "E26" => {
            eprintln!("Insufficient memory requested. Such error appears when the user requests to launch an enclave with not enough memory. The enclave memory should be at least equal to the size of the EIF file used for launching the enclave.\n\tExample: (EIF file size: 11MB) `nitro-cli run-enclave --cpu-count 2 --memory 5 --eif-path /path/to/my/eif`. In this case, the user requested to run an enclave with only 5MB of memory, whereas the EIF file alone requires 11MB.");
        }
        "E27" => {
            eprintln!("Insufficient memory available. Such error appears when the user requests to launch an enclave with more memory than available. The enclave memory should be at most equal to the size of the configured hugepage memory.\n\tExample: (previously configured 80MB of hugepage memory) `nitro-cli run-enclave --cpu-count 2 --memory 100 --eif-path /path/to/my/eif`. In this case, the user requested to run an enclave with 100MB of memory, whereas the system has only 80MB available for enclaves. As a solution, (re)configure the Nitro Enclaves environment, specifying a higher value for the available memory.");
        }
        "E28" => {
            eprintln!("Invalid enclave descriptor. Such error appears when the NE_CREATE_VM ioctl returns with an error.");
        }
        "E29" => {
            eprintln!("Ioctl failure. Such error is used as a general ioctl error and appears whenever an ioctl fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E30" => {
            eprintln!("Ioctl image get load info failure. Such error appears when the ioctl used for getting the memory load information fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E31" => {
            eprintln!("Ioctl set memory region failure. Such error appears when the ioctl used for setting a given memory region fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E32" => {
            eprintln!("Ioctl add vCPU failure. Such error appears when the ioctl used for adding a vCPU fails. In this case, the error backtrace provides detailed information on what specifically failed during the ioctl.");
        }
        "E33" => {
            eprintln!("Ioctl start enclave failure. Such error appears when the ioctl used for starting an enclave fails. In this case, the error backtrace provides details information on what specifically failed during the ioctl.");
        }
        "E34" => {
            eprintln!("Memory overflow. Such error may appear during loading the EIF in the memory regions which will be conceded to the future enclave, if the regions offset plus the EIF file size exceeds the maximum address of the target platform.");
        }
        "E35" => {
            eprintln!("EIF file parsing error. Such errors appear when attempting to fill a memory region with a section of the EIF file, but reading the entire section fails. This might indicate that the required hugepages are not available.");
        }
        "E36" => {
            eprintln!("Enclave boot failure. Such error appears when attempting to receive the `ready` signal from a freshly booted enclave. It arises in several contexts, for instance, when the enclave is booted from an invalid EIF file and the enclave process immediately exits, failing to submit the `ready` signal. In this case, the error backtrace provides detailed information on what specifically failed during the enclave boot process.");
        }
        "E37" => {
            eprintln!("Enclave event wait error. Such error appears when monitoring an enclave descriptor for events fails.");
        }
        "E38" => {
            eprintln!("Enclave process command not executed error. Such error appears when at least one enclave fails to provide the description information.");
        }
        "E39" => {
            eprintln!("Enclave process connection failure. Such error appears when the enclave manager fails to connect to at least one enclave process for retrieving the description information.");
        }
        "E40" => {
            eprintln!("Socket path not found. Such error appears when the Nitro CLI process fails to build the corresponding socket path starting from a given enclave ID.");
        }
        "E41" => {
            eprintln!("Enclave process send reply failure. Such error appears when the enclave process fails to submit the status code to the Nitro CLI process after performing a run / describe / terminate command.");
        }
        "E42" => {
            eprintln!(
                "Enclave mmap error. Such error appears when allocating the enclave memory fails."
            );
        }
        "E43" => {
            eprintln!(
                "Enclave munmap error. Such error appears when unmapping the enclave memory fails."
            );
        }
        "E44" => {
            eprintln!("Enclave console connection failure. Such error appears when the Nitro CLI process fails to establish a connection to a running enclave's console.");
        }
        "E45" => {
            eprintln!("Enclave console read error. Such error appears when reading from a running enclave's console fails.");
        }
        "E46" => {
            eprintln!("Enclave console write output error. Such error appears when writing the information retrieved from a running enclave's console (to a given stream) fails.");
        }
        "E47" => {
            eprintln!("Integer parsing error. Such error appears when trying to connect to a running enclave's console, but the enclave CID cannot be parsed correctly.");
        }
        "E48" => {
            eprintln!("EIF building error. Such error appears when trying to build an EIF file. In this case, the error backtrace provides detailed information on the failure reason.");
        }
        "E49" => {
            eprintln!("Docker image build error. Such error appears when trying to build and EIF file, but building the corresponding docker image fails. In this case, the error backtrace provides detailed information on the failure reason.");
        }
        "E50" => {
            eprintln!("Docker image pull error. Such error appears when trying to build an EIF file, but pulling the corresponding docker image fails. In this case, the error backtrace provides detailed informatino on the failure reason.");
        }
        "E51" => {
            eprintln!("Artifacts path environment variable not set. Such error appears when trying to build an EIF file, but the artifacts path environment variable is not set.");
        }
        "E52" => {
            eprintln!("Blobs path environment variable not set. Such error appears when trying to build an EIF file, but the blobs path environment variable is not set.");
        }
        "E53" => {
            eprintln!("Clock skew error. Such error appears when continuously reading from a running enclave's console, but measuring the time elapsed between consecutive reads failed.");
        }
        "E54" => {
            eprintln!("Signal masking error. Such error appears if attempting to mask specific signals before creating an enclave process fails.");
        }
        "E55" => {
            eprintln!("Signal unmasking error. Such error appears if attempting to unmask specific signals after creating an enclave process fails.");
        }
        "E56" => {
            eprintln!("Logger error. Such error appears when attempting to initialize the underlying logging system fails.");
        }
        _ => {
            eprintln!("No such error code {}", error_code_str);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NitroCliFailure;
    use crate::common::document_errors::construct_backtrace;

    #[test]
    fn test_construct_backtrace() {
        let failure = NitroCliFailure::new()
            .set_action(String::from("ABCD"))
            .add_subaction(String::from("EFGH"))
            .add_subaction(String::from("IJKL"))
            .set_file_and_line("/path/file.txt", 1234);
        // "  Action: ABCD
        //    Subactions:
        //      IJKL
        //      EFGH
        //    Root error file: /path/file.txt
        //    Root error line: 1234
        //    Version: X.Y.Z"
        let expected = format!("  Action: ABCD\n  Subactions:\n    IJKL\n    EFGH\n  Root error file: /path/file.txt\n  Root error line: 1234\n  Version: {}",
            env!("CARGO_PKG_VERSION"));
        assert_eq!(expected, construct_backtrace(&failure));
    }
}
