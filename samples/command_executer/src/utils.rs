use log::error;

pub trait ExitGracefully<T, E> {
    fn ok_or_exit(self, message: &str) -> T;
}

impl<T, E: std::fmt::Debug> ExitGracefully<T, E> for Result<T, E> {
    fn ok_or_exit(self, message: &str) -> T {
        match self {
            Ok(val) => val,
            Err(err) => {
                error!("{:?}: {}", err, message);
                std::process::exit(1);
            }
        }
    }
}

#[macro_export]
macro_rules! create_app {
    () => {
        App::new("Vsock Tool")
            .about("Tool that runs commands inside the enclave")
            .setting(AppSettings::ArgRequiredElseHelp)
            .version(env!("CARGO_PKG_VERSION"))
            .subcommand(
                SubCommand::with_name("listen")
                    .about("Listen on a given port")
                    .arg(
                        Arg::with_name("port")
                            .long("port")
                            .help("port")
                            .takes_value(true)
                            .required(true),
                    ),
            )
            .subcommand(
                SubCommand::with_name("run")
                    .about("Run a command inside the enclave")
                    .arg(
                        Arg::with_name("port")
                            .long("port")
                            .help("port")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("cid")
                            .long("cid")
                            .help("cid")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("command")
                            .long("command")
                            .help("command")
                            .takes_value(true)
                            .required(true),
                    ),
            )
            .subcommand(
                SubCommand::with_name("recv-file")
                    .about("Receive a file from the enclave")
                    .arg(
                        Arg::with_name("port")
                            .long("port")
                            .help("port")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("cid")
                            .long("cid")
                            .help("cid")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("localpath")
                            .long("localpath")
                            .help("localpath")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("remotepath")
                            .long("remotepath")
                            .help("remotepath")
                            .takes_value(true)
                            .required(true),
                    ),
            )
            .subcommand(
                SubCommand::with_name("send-file")
                    .about("Send a file to the enclave")
                    .arg(
                        Arg::with_name("port")
                            .long("port")
                            .help("port")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("cid")
                            .long("cid")
                            .help("cid")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("localpath")
                            .long("localpath")
                            .help("localpath")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("remotepath")
                            .long("remotepath")
                            .help("remotepath")
                            .takes_value(true)
                            .required(true),
                    ),
            )
    };
}
