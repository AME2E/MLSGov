# Reporting

We detail here how content reporting works in our framework. Recall that
actions are the fundamental message type that can be sent to groups. Each
action will have a reporting signature attached to it that can be verified
by a judging endpoint. There are two types of judging endpoints: community
moderators and platform moderators.

## Community moderation flow

Community moderators receive reports via group messages. To issue a report
to a community moderator, a user creates a group with (some subset of) the
community moderators and sends a `Report` action which contains the message
being reported along with the signature for verifying the report.

In response to reports, community moderators may remove members from groups
or from the community as a whole. If they suspect that a report indicates a
violation of platform guidelines, community moderators can forward reports
to platform moderators. In order to forward a report, a community moderator
creates a group with a platform moderator and sends the received report to
the group.

## Platform moderation flow

Platform moderators receive reports via group messages. Users within a
community can send reports directly to platform moderators if they suspect
a message violates platform guidelines.

In response to reports that indicate a user has violated platform terms,
platform moderators may remove users from the platform. This is done by
removing a user's identity mapping from the AS and adding the user's
existing credentials to the DS block-list. Users who attempt to send a
message to a deplatformed user will be notified of removal and will be
encouraged to rotate their cryptographic key material to exclude the
deplatformed user from any existing groups.

Platform moderators can also forward reports to community moderators. In
a report, the reporter can specify a community moderator point of contact
that the platform moderator can touch base with if they deem it necessary.

Each community needs at least one designated point of contact in order to
allow the platform to forward reports to community moderators. This allows
the platform to encourage a community moderator to take action at the
community level in response to reports that do not violate platform
guidelines.

## Platform moderation infrastructure

For now, we consider the "platform moderator" to be a monolithic entity.
Logically speaking, there is one platform moderator, however behind the
scenes, this moderation entity can be multiplexed to a team of platform
moderators.

The platform moderation interface consists of a special client that can
mediate user access to the platform. We refer to this client as the
"moderation service" (MS). As mentioned above, deplatforming a user requires changes to the DS and AS. Therefore, we define MS-DS and MS-AS
protocols that enable the MS to make these changes. Alongside this client,
platform moderators use a regular client interface for receiving,
forwarding, and responding to reports.

Note that this model is compatible with architectures in which the MS is
run by a third party as opposed to the platform itself.

## Implementations

The reporting flow is implemented using the following key components:

- `ReportAction` in `corelib/src/client_api/actions/mod.rs`: An action type for reporting messages. It contains the serialized action being reported (`ver_action_str`) and the reason for reporting.
- Report handling in `corelib/src/client_api/mod.rs`:
  - The `check_action_msg_and_get_mls` function checks if an action is a `Report`. If so, it signs the reported action and includes the signature in the `Report`.
  - The `parse_incoming_onwire_msgs` function, when processing a received `Report`, verifies the signature on the reported action before executing the report.
- Moderation service (MS) client: A special client that can send moderation commands to the AS and DS. Not fully implemented in the current code, but would include:
  - Functions to remove a user's identity from the AS (`UserCredential` struct)
  - Functions to add a user's credentials to a block-list on the DS (`DeliveryServiceState` struct)
  - A function to notify a user that they have been deplatformed
- Community moderator flow:
  - Moderators are designated by assigning them the "Mod" role using `SetUserRoleAction`
  - They receive `Report` actions in the groups they moderate
  - They can remove reported users using `KickAction` and `RemoveAction`
  - They can forward reports to the MS by creating a new group with the MS and sending the `Report` there
- Platform moderator flow:
  - Platform moderators use a regular client to receive `Report` actions
  - They can deplatform users by sending commands from the MS client to the AS and DS
  - They can forward reports to community mods by creating a group with the mod and sending the `Report` there

