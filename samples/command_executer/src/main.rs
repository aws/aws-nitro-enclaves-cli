use clap::{App, AppSettings, Arg, SubCommand};

use command_executer::command_parser::{FileArgs, ListenArgs, RunArgs};
use command_executer::create_app;
use command_executer::utils::ExitGracefully;
use command_executer::{listen, recv_file, run, send_file};

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
            let rc = run(run_args).ok_or_exit(args.usage());
            std::process::exit(rc);
        }
        ("recv-file", Some(args)) => {
            let subcmd_args = FileArgs::new_with(args).ok_or_exit(args.usage());
            recv_file(subcmd_args).ok_or_exit(args.usage());
        }
        ("send-file", Some(args)) => {
            let subcmd_args = FileArgs::new_with(args).ok_or_exit(args.usage());
            send_file(subcmd_args).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}
