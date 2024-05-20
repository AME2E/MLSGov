# The Journey of a Message

In this section, we outline in detail the code paths that a message traverses
from the time it is sent to the time that it is received. We will focus on
the client code in particular.

## Sender-Client Side

When a client wants to send a message, it calls one of the message sending functions in `corelib/src/client_api/mod.rs` such as `send_text_msg_mls` or `check_action_msg_and_get_mls`. These functions:

1. Create an `ActionMsg` object representing the message (e.g. `TextMsgAction` for text messages).
2. Pass the `ActionMsg` to `bytes_to_group_message` which:
   - Serializes the action to bytes
   - Creates an MLS `ApplicationMessage` containing those bytes
   - Encrypts it to all group members using the MLS group state
3. Wrap the encrypted message in a `GroupMessage` enum.
4. Create an `OnWireMessage` (`UserStandardSend` for unordered messages, `UserReliableSend` for ordered) containing the `GroupMessage` and list of recipients.
5. Send this `OnWireMessage` to the delivery service over a WebSocket connection.

## Delivery-Service Side

On the delivery service side (`delivery_service/src/main.rs`), when it receives an `OnWireMessage`:

1. It passes it to `handle_onwire_msg_ds_local` in `corelib/src/servers_api/mod.rs`.
2. For `UserStandardSend`, it stores the message in the `unordered_message_indvl_queues` for each recipient. For `UserReliableSend`, it appends the message to the `groups_to_ordered_messages` list for that group.
3. It generates a `DSResult` message acknowledging the send and sends it back to the client.

## Receiving-Client Side

On the receiving client, it syncs with the DS by sending a `UserSync` message. The DS responds with:

1. All pending unordered messages for that user from `unordered_message_indvl_queues` in `DSRelayedUserMsg` messages.
2. If the user was attempting an `ReliableSend`, the user will receive prior, unseen ordered messages for groups the user is in from `groups_to_ordered_messages` in the `preceding_and_sent_ordered_msgs` field of the `DSResult`.

The receiving client passes these messages to `parse_incoming_onwire_msgs` in `corelib/src/client_api/mod.rs` which:

1. For each `DSRelayedUserMsg`, decrypts the message using the MLS group state and processes the decrypted `ActionMsg`.
2. For each message in `preceding_and_sent_ordered_msgs`, decrypts and processes each ordered message in order like in (1).

Processing an `ActionMsg` involves updating the local client state (e.g. storing the message in history) and possibly triggering further actions (e.g. updating group state based on an action).

# 