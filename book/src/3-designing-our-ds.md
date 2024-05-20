# Designing our Delivery Service

Recall that the delivery service is the one that does the actual delivery of messages.

## Storing `KeyPackage`s

But, we before we can deliver messages, we need to be able to encrypt them to the recipient. MLS does this via [`KeyPackage`](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-key-packages)s which contain a X25519 public key which allows encrypting data to the recipient. To ensure authenticity, the `KeyPackage`s are signed with the user's `Credential` (which is retrieved from the Authentication Service). As with other KEM/DH public keys, to prevent replay attacks, a `KeyPackage` should only be used once. So, the user periodically uploads many `KeyPackages`s to the delivery service, so they can receive messages from many new senders.

Similar to the `/v1/user` API, we build a `/v1/device/upload_keypackages` API that takes a `(username, list of keypackages)` and stores it in a hashmap indexed by the username; and a `/v1/device/retrieve` API that takes a username and returns one KeyPackage which is then removed from the list.

Notice that this assumes that each user only has one device. But, in the future, we may want to support multiple devices, where we need to maintain multiple lists of KeyPackages for each user. In other words, we would have `HashMapOfUsers<HashMapOfUsersDevices<KeyPackage>>`.

The key package handling is implemented in the `delivery_service/src/main.rs` file. The `DeliveryServiceState` struct defined in `corelib/src/servers_api/ds_structs/mod.rs` stores the key packages for each user in the `user_key_packages` field.

The relevant APIs are:

- `UserKeyPackagesForDS`: Allows a user to upload their key packages to the DS. These are stored in `user_key_packages`.

- `DSKeyPackageResponse`: Returns key packages for requested users. The key packages are removed from `user_key_packages` after sending.

## Tradeoff 1: Server versus Client Fan-Out

In the traditional Signal setting, we use the KeyPackages to establish an encrypted one-to-one connection to the recipient. This implies that if we want to send a message to a group with 100 participants, we need to re-encrypt the message 100 times for each encrypted one-to-one channel.

MLS improves on this using a notion of *sender keys* where each sender in a group has a "sender key", which they broadcast to group participants via the previously established encrypted one-to-one channels, and they encrypt under that key. See [this blog post](https://mrosenberg.pub/cryptography/2019/07/10/molasses.html) for more on how sender keys work and how MLS generates them.

Going back to the 100 user group example, with sender keys, the sender no longer needs to encrypt 100 times. But, to take full advantage of this paradigm they need the delivery service to support one-to-many channels where they can provide `(message, list of recipients)` and the delivery service forwards the message to all the recipients.

The delivery service implements this one-to-many forwarding. When it receives a `UserStandardSend` or `UserReliableSend` message, it delivers the message to all recipients specified in the `recipients` field. This allows the client to encrypt the message just once using MLS.

## Tradeoff 2: Thick versus Thin Delivery

A *thin delivery service* is one that has limited state, it just process sync and other requests with all devices and queues messages sent to it to the cited user. Notice that we do not trust the delivery service too much, specifically, it may be "curious" or as some would say, "its data can be subpoenaed." See [signal.com/bigbrother](https://signal.org/bigbrother/).

However, as noted in [this blog post](https://signal.org/blog/signal-private-group-system/) it is hard to build a scalable group messaging system based on just one-to-many communication channels and not shared, server-stored state because clients get out of sync. As mentioned in the blog post, Signal solved this problem using shared encrypted state and zero-knowledge proofs on that encrypted state (like Alice is Mod.) This allows Signal to have a fully-featured *thick delivery service* without storing any more information than a thin delivery service using the ✨magic✨ of cryptography.

But, for simplicity, for now, we apply a thin delivery scheme that requires every message to declare all its recipients. In the future, we can use Signal-style ideas to reduce message overheads. 

Our delivery service is relatively thin - it does not store any unencrypted message contents. It just queues messages for delivery to users in `unordered_message_indvl_queues` and `groups_to_ordered_messages`. The clients are responsible for specifying all recipients for each message. 

## Tradeoff 3: Epoch Tracking versus Proposal Ordering

To ensure that decentralized (and honest) clients share the same group states and avoid branching, MLS Group keeps track of [transcript hashes](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-transcript-hashes) over all Proposal and Commits (Ordered Messages), with every merge of commits incrementing a group epoch, a plaintext meta data in all encrypted MLS messages. When a client sends in a Proposal or Commit, the delivery service can help clients avoid merge conflicts by checking if the associated Proposal or Commit is exactly 1 above the current epoch number of this group tracked by it. If the check passes, the delivery service will atomically increment the epoch of the group, and inform the client to proceed with merging. If the check fails, the delivery service will reject the Proposal or Commit, and the client must clear the commit (and could reattempt). 

However, this epoch approach is vulnerable to malformed requests: if an dishonest user uploads a bad Proposal or Commit (i.e. one that will be rejected by other honest clients for the same group based on group policies and newest states), the delivery service, unaware of the policy decisions, will accept it and increment the epoch in its record. As a result, all clients will stay at the old epoch and not be able to submit any new Commit or Proposal (as their epoch will not be high enough). An epoch-reverting mechanism also seems infeasible as the delivery service is not designed to enforce authentications, and allowing arbitrary reverting could again be abused by malicious clients.

Instead, we ignore epoches and have the delivery service accepts all Commit and Proposal, and offer conflict prevention via pre-merge sync. When a client sends new Commit and Proposal, the delivery service guarantees to order it and send all new Commits and Proposals which precedes it but unknown to the client, before the client merge their new commit. See more details in our [Conflict Resolution chapter](./12-conflict-resolution.md).

The delivery service orders messages using the `groups_to_ordered_messages` field in `DeliveryServiceState`. When it receives an ordered message (`UserReliableSend`), it appends it to the list of ordered messages for that group. 

When a client sends a new ordered message, the DS sends back all preceding ordered messages for that group that the client hasn't seen yet in the `DSResult` message. The client processes these before merging its own commit.

## Tradeoff 4: Sealed Sender versus Clear Sender

A *Sealed Sender* messaging scheme is one where all servers involved in relaying a message would not know who sent it, at least not explicitly (but servers might be able to infer some information via e.g. traffic analysis). Signal discussed how it uses it [in this blog](https://signal.org/blog/sealed-sender/)

Using a thin delivery mechanism (discussed above in Tradeoff 2), we allow sealed senders in all AppMessage. However, for messages requiring strong ordering (i.e. Proposal and Commit), clear sender is necessary. 

The delivery service allows sealed sender for `UserStandardSend` messages but requires a clear sender for `UserReliableSend` messages which are used for ordered actions.
