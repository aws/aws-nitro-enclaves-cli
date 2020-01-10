use clap::{App, AppSettings, Arg, SubCommand};

use command_executer::command_parser::{ListenArgs, RecvFileArgs, RunArgs};
use command_executer::create_app;
use command_executer::utils::ExitGracefully;
use command_executer::{listen, recv_file, run};

fn main() {
    let app = create_app!();
    let args = app.get_matches();

    match args.subcommand() {
        ("listen", Some(args)) => {
            let listen_args = ListenArgs::new_with(args).ok_or_exit(args.usage());
            listen(listen_args).ok_or_exit(args.usage());
        }
        ("run", Some(args)) => {
            let run_args = RunArgs::new_with(args).ok_or_exit(args.usage());
            run(run_args).ok_or_exit(args.usage());
        }
        ("recv-file", Some(args)) => {
            let subcmd_args = RecvFileArgs::new_with(args).ok_or_exit(args.usage());
            recv_file(subcmd_args).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}
