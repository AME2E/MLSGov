use clap::Parser;
use clap::Subcommand;

use corelib::client_api::actions::{ActionType, VoteValue};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, propagate_version = true)]
pub(crate) struct ClientInput {
    /// Command to be executed
    #[clap(subcommand)]
    pub(crate) command: ClientInputCommand,

    /// Repeatable flag to turn verbose output on (Max: 2)
    #[clap(short, long, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    /// produce output in JSON to interface with other scripts
    #[clap(short, long)]
    pub(crate) json: bool,

    /// No sync before executing the subcommand. Error/Overridden when subcommand is sync.
    #[clap(short, long)]
    pub(crate) no_sync: bool,

    /// Skip storing local states. Dev only. Can branch group states if messages are ordered
    #[clap(short, long)]
    pub(crate) skip_store: bool,

    /// Skip updating group message history. Dev only. Avoid varying loading time
    #[clap(short, long)]
    pub(crate) skip_history_msg_update: bool,

    /// Ignore the local state and start fresh. Overwrite the local state if saving
    #[clap(short, long)]
    pub(crate) fresh_start: bool,

    /// Whether to allow auto retry using the same connection if certain operations failed
    #[clap(short, long)]
    pub(crate) auto_retry: bool,

    /// Max seconds to randomly delay between retries. Non-negative input only.
    /// Delay = min(randint(0, 2^#trial)*window_size, max_delay)
    #[arg(short, long, default_value_t = 0f32)]
    pub(crate) max_delay: f32,

    /// coefficient to trial number in calculating delay between retries. Non-negatives only.
    /// Trial starts from 0.
    /// Delay = min(randint(0, 2^#trial)*window_size, max_delay)
    #[arg(short, long, default_value_t = 0f32)]
    pub(crate) window_size: f32,
}

#[derive(Subcommand, PartialEq, Debug)]
pub(crate) enum ClientInputCommand {
    /// generates a new credential, saves to local configuration,
    /// and uploads the public key to the authentication service
    Register {
        #[clap(value_parser)]
        name: String,
    },
    /// creates a new MLS group
    Create {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
    },
    /// syncs the client and prints updates. note sync is called automatically before all commands
    Sync,
    /// pre-authoring an invite of a user to a group, not informing the invitee.
    Invite {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser, value_delimiter = ',')]
        invitee_names: Vec<String>,
    },
    /// Actually adding an invite of a user to a group, informing the invitee. Prerequisite: `Invite`
    Add {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser, value_delimiter = ',')]
        invitee_names: Vec<String>,
    },
    /// send a message to a group
    Send {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        message: String,
    },
    /// read a message from a group
    Read {
        #[clap(value_parser)]
        community_id: String,

        #[clap(value_parser)]
        group_id: String,

        #[clap(subcommand)]
        option: Option<ReadOption>,
    },
    /// pre-leave a group. Serve as pre-authorization for `Remove` self
    Leave {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
    },
    /// accept a group invite
    Accept {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
    },
    /// pre-reject a group invite. Serve as pre-authorization for `Remove` self
    Decline {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
    },
    /// pre-kick a user from a group. Serve as pre-authorization for `Remove` the user
    Kick {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        member_name: String,
    },
    /// The actual (credential-level) removal of a user (or self) from a group
    Remove {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        member_name: String,
    },
    /// promote a user to a higher role in a group
    SetRole {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        member_name: String,
        #[clap(value_parser)]
        new_role: String,
    },
    /// rename a group within a community
    RenameGroup {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        new_group_id: String,
    },
    /// change the group topic within a community
    ChangeGroupTopic {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        new_group_topic: String,
    },
    /// braodcast new update to group state
    UpdateGroupState {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
    },
    /// displays the group state
    ShowGroupState {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
    },
    /// votes on a proposed action
    Vote {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        vote_value: VoteValue,
        #[clap(value_parser)]
        proposed_action_id: String,
        #[clap(value_parser)]
        proposed_action_type: ActionType,
    },
    /// define a new role as a set of `ActionType`s
    DefRole {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        role_name: String,
        #[clap(value_parser)]
        action_types: Vec<ActionType>,
    },
    Report {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        ver_action_str: String,
        #[clap(value_parser)]
        reason: String,
    },
    Custom {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        data: String,
    },
    TakedownText {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        message_id: String,
        #[clap(value_parser)]
        reason: String,
    },
    /// Proposes a vote to be cast on a proposed action
    ProposeVote {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
        #[clap(value_parser)]
        vote_value: VoteValue,
        #[clap(value_parser)]
        proposed_action_id: String,
        #[clap(value_parser)]
        proposed_action_type: ActionType,
    },
    /// Creates a commit for all pending votes
    CommitPendingVotes {
        #[clap(value_parser)]
        community_id: String,
        #[clap(value_parser)]
        group_id: String,
    },
}

#[derive(Subcommand, Eq, PartialEq, Debug, Clone)]
#[clap(args_conflicts_with_subcommands = false)] //If this is true, [Read] is [group_id] XOR [option]
pub enum ReadOption {
    Unread, // Current `Default`. See [ReadOption::default()]
    Last {
        #[clap(value_parser)]
        n_message: usize,
    },
    All,
}

impl Default for ReadOption {
    fn default() -> Self {
        Self::Unread
    }
}

impl ClientInputCommand {
    pub(crate) fn needs_pre_sync(&self) -> bool {
        match self {
            ClientInputCommand::Register { .. } => false,
            ClientInputCommand::Create { .. }
            | ClientInputCommand::Sync
            | ClientInputCommand::Invite { .. }
            | ClientInputCommand::Send { .. }
            | ClientInputCommand::Read { .. }
            | ClientInputCommand::Leave { .. }
            | ClientInputCommand::Accept { .. }
            | ClientInputCommand::Decline { .. }
            | ClientInputCommand::Kick { .. }
            | ClientInputCommand::SetRole { .. }
            | ClientInputCommand::ShowGroupState { .. }
            | ClientInputCommand::UpdateGroupState { .. }
            | ClientInputCommand::RenameGroup { .. }
            | ClientInputCommand::Add { .. }
            | ClientInputCommand::Vote { .. }
            | ClientInputCommand::Remove { .. }
            | ClientInputCommand::DefRole { .. }
            | ClientInputCommand::Report { .. }
            | ClientInputCommand::Custom { .. }
            | ClientInputCommand::TakedownText { .. }
            | ClientInputCommand::ChangeGroupTopic { .. }
            | ClientInputCommand::ProposeVote { .. }
            | ClientInputCommand::CommitPendingVotes { .. } => true,
        }
    }
}
