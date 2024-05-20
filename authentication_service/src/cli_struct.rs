use clap::Parser;

#[derive(Parser, Debug, Default)]
#[clap(author, version, about, long_about = None, propagate_version = true)]
pub(crate) struct CliAS {
    /// Repeatable flag to turn verbose output on (Max: 2)
    #[clap(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Use String as command delivery method instead of struct
    #[clap(short, long)]
    pub fresh_start: bool,

    #[clap(short, long)]
    /// Skip storing persistent states entirely
    pub non_persistent: bool,
}
