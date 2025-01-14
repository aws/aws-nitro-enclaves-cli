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
        Command::new("Vsock Tool")
            .about("Tool that runs commands inside the enclave")
            .arg_required_else_help(true)
            .version(env!("CARGO_PKG_VERSION"))
            .subcommand(
                Command::new("listen")
                    .about("Listen on a given port")
                    .arg(Arg::new("port").long("port").help("port").required(true)),
            )
            .subcommand(
                Command::new("run")
                    .about("Run a command inside the enclave")
                    .arg(Arg::new("port").long("port").help("port").required(true))
                    .arg(Arg::new("cid").long("cid").help("cid").required(true))
                    .arg(
                        Arg::new("command")
                            .long("command")
                            .help("command")
                            .required(true),
                    )
                    .arg(
                        Arg::new("no-wait")
                            .long("no-wait")
                            .help("command-executer won't wait the command's result")
                            .action(ArgAction::SetTrue),
                    ),
            )
            .subcommand(
                Command::new("recv-file")
                    .about("Receive a file from the enclave")
                    .arg(Arg::new("port").long("port").help("port").required(true))
                    .arg(Arg::new("cid").long("cid").help("cid").required(true))
                    .arg(
                        Arg::new("localpath")
                            .long("localpath")
                            .help("localpath")
                            .required(true),
                    )
                    .arg(
                        Arg::new("remotepath")
                            .long("remotepath")
                            .help("remotepath")
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("send-file")
                    .about("Send a file to the enclave")
                    .arg(Arg::new("port").long("port").help("port").required(true))
                    .arg(Arg::new("cid").long("cid").help("cid").required(true))
                    .arg(
                        Arg::new("localpath")
                            .long("localpath")
                            .help("localpath")
                            .required(true),
                    )
                    .arg(
                        Arg::new("remotepath")
                            .long("remotepath")
                            .help("remotepath")
                            .required(true),
                    ),
            )
    };
}
