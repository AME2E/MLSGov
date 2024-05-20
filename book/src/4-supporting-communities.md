# Supporting Communities

But, groups are not sufficient for modern communication, just look at
[Discord's servers](https://support.discord.com/hc/en-us/articles/360045138571-Beginner-s-Guide-to-Discord#h_efc9b7bc-47bc-4212-8b9c-c0fa76573cfe),
[Keybase's teams](https://keybase.io/blog/introducing-keybase-teams),
[Matrix's spaces](https://matrix.org/blog/2021/05/17/the-matrix-space-beta),
[Slack's workspaces](https://slack.com/help/articles/206845317-Create-a-Slack-workspace), and
[Zulip's organizations](https://zulip.com/help/getting-your-organization-started-with-zulip).
Even WhatsApp has announced its take on this concept called [Communities](https://blog.whatsapp.com/sharing-our-vision-for-communities-on-whatsapp).

Like with groups, let's stick to a plaintext hashmap on the delivery service for implementing communities: specifically a map from `community_id` to `(community name, list of members, list of mods, list of (private) channels, other shared state)`. Note that all states other than the `list of members` should be encrypted and hence not viewable by DS. Other shared state might include, for example, `member reputation`, `community rules` . Also note that we use group and channels interchangibly.

All members of a community will and must join `#general`-equivalent, a group in the community. Any member can ask to be invited in `#general`; this is like being asked to admit in a Zoom meeting.

Channel and private channel data would be extensions of the community structure, and their operations augmented to ensure that their membership is always a subset of the community.

To support the above features, clients would have the capability to

- `create`, `leave`, and `delete ` community, and `invite` new members to the community and invitees can `accept` or `decline`
- `create ` , `leave`, and `delete ` groups inside community, and `invite` new members to groups and invitees can `accept` or `decline`
- `kick` other member from community (authorized members only)
- `send` and `sync` (and then locally `read`) messages in the community

Note that a hallmark of our platform is that the servers are not (explicitly)
informed of the existence of community and groups -- 
e.g. the delivery service mainly just sends some message to target recipients. Hence `create` is also a local command too.

## Invite/Accept/Decline Infrastructure

Unlike most actions, an invitation entails both an action and also an MLS predefined add operation (See [Add Proposal](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-add)). Hence inviting + adding a member to a group is done through the following steps:

1. The inviter obtains and locally stores one KeyPackage of the invitee from the Delivery Service. If there is none on the Delivery Service, the inviter must wait.

2. The inviter sends an `Invite` PlatformAction to all group members. The `Invite Action` contains the KeyPackage of the invitee. Note that this action serves as a pre-authorization of adding members.

3. After the approval of the `Invite Action` (if required), the action will execute by adding the invitee's UserID to a pre-approved list in the group state of each client.

4. The inviter (or any other group member) generates the `Add Proposal + Commit` using the invitee's KeyPackage. All members generating or receiving this `Add` commit must pop the invitee's UserID out of the pre-approved list. A `Welcome` message generated by OpenMLS will be sent to the invitee. Retries if the commit does not go through. Once the `Add` message was sent without conflicts, the `Add` sender also needs to needs to broadcast out their local current group governance state (`SharedGroupState`) using an `UpdateGroupState` Action (Unordered). The group state action
   
   1. Must share the same group epoch with the Welcome message.
   2. Must not changed since the `Add` message generation time).

5. The invitee receives the `Welcome` message after syncing and the client creates and stores the group states locally, and prompt user to `Accept` or `Decline`. When the user Accept or Decline, the client first try to recover all group states from a broadcasted message by processing all unordered messages. If the group state is still not activated, the client restores all popped messages and informs the user "Cannot accept/decline". If the `UpdateGroupState` was successfully activated, the user generates the following:
   
   1. The `Accept Action` is unordered and like a No-op. Could serve as a notification to all other members.
   2. The `Decline Action` is parallel of an `Invite Action`. The action only put the user's name to a `to_remove list`, and then to actually remove oneself from the MlsGroup, the user must send the MlsMessage generated by the `MlsGroup` `leave_group()` method (by using `Remove` on the client side). Whenever if any client generates/receives a `Leave Proposal`, the client checks if the to-be-removed member's name is on the `to_remove list` . If so, pops the name and authorizes, and ignore the proposal if not.

For all other group members:

- Whenever they receive a `governance_state` copy through any message, the client checks if the copy is the same as theirs. If not, print a warning message with the source's UserID.
- Whenever they receive a `Add Proposal + Commit`, they check if the member is on the pre-approved list. If not, reject the Add Commit. (If so, again, they will merge the commit and pop the invitee's UserID from the list)
- Also they respond to `Accept`, `Decline`, and `Leave` as mentioned above.

## Implementations

The invite flow is implemented across multiple functions:

- `pre_add_invite_msg` in `corelib/src/client_api/mod.rs`: Generates the `Invite` action message. It fetches the invitee's key package and includes it in the action.
- `add_msg` in `corelib/src/client_api/mod.rs`: Generates the actual `Add` proposal and commit message to add the invitee to the group.
- `accept_msg`, `pre_decline_msg` in `corelib/src/client_api/mod.rs`: Generates the `Accept` and `Decline` action messages respectively.
- `remove_other_or_self_msg` in `corelib/src/client_api/mod.rs`: Generates the MLS message to actually remove a member from the group.

The delivery service stores invites for each user in the `invite_indvl_queues` field of `DeliveryServiceState`. When a user syncs, the DS sends back all pending invites for that user.