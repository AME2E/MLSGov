# Message Format

## On Wire Message Types

- `OnWireMessageWithMetaData` is an `OnWireMessage` with extra data like `sender_timestamp` and `version`.

- `OnWireMessage` specifies user's requests or server's responses. For example, user might `register`, `sync`, `send` `GroupMessage`, and the server might respond with `DSResult` and relay other users' `GroupMessage` or `Welcome`.

- [`Welcome`](https://docs.rs/openmls/latest/openmls/messages/struct.Welcome.html) is an OpenMLS API object generated based on an invitee's [`KeyPackage`](https://docs.rs/openmls/latest/openmls/key_packages/struct.KeyPackage.html) so that the invitee can "join the group" as they can decipher all future messages.

- `GroupMessage` is either an encrypted `MlsMessageOut` along with the group ID and sender. The Delivery Service should not need or know any details below the level `GroupMessage`.

- [`MlsMessageOut`](https://docs.rs/openmls/latest/openmls/prelude/struct.MlsMessageOut.html) is an OpenMLS API object that is encrypted and [either](https://docs.rs/openmls/latest/openmls/framing/enum.ProcessedMessage.html) specifies a [proposal](https://docs.rs/openmls/latest/openmls/messages/proposals/enum.Proposal.html), an `ApplicationMessage`, or a commit. In our case, the `ApplicationMessage` would contain an encoded `UnorderedPrivateMessage` or `OrderedPrivateMessage`.

- `UnorderedPrivateMessage` is a structure that encodes user-initiated actions that do not involve membership changes or require strong ordering guarantees. This includes regular text messages (`UnorderedMsgContent::Text`), text-based actions like reporting (`UnorderedMsgContent::TextAction`), updates to the shared group state (`UnorderedMsgContent::GroupState`), and unsigned actions (`UnorderedMsgContent::UnsignedAction`).

- `OrderedPrivateMessage` is a structure for messages that require strong ordering guarantees, like Actions that modify group membership or roles. It contains a single `VerifiableAction` or a vector of `VerifiableAction`s.

- `VerifiableAction` is a wrapper around `ActionMsg` that includes a signature for authenticity.

- `ActionMsg` is an enum representing different types of actions a user can take, such as `TextMsg`, `RenameGroup`, `Invite`, `Kick`, `DefRole`, `SetUserRole`, etc. Each variant contains the necessary data for that action. The `CustomAction` variant allows for extensibility.
