# Conflict Resolution

Note: with the introudction of platform actions in [Chapter 9](./9-platform-actions.md), we use `Ordered Action` to refer to anything sent with transcript hash guarantee (`Proposal and Commit`, `Handshake Message`, or `Platform Action` all refer to this) and expecting the delivery service to maintain an order specified below.

## Enforce Ordering

To avoid two clients submitting ordered actions at the same time branch their local states unexpectedly, rather than rejecting any potentially conflicted ordered actions, we have the delivery service accept and enforce an ordering of all incoming actions, and ensure that the clients have all ordered actions preceding their new one before they merge.

The delivery service guarantees to handle ordered action fan-outs one at a time for each group. When handling one, after obtaning a lock to ensure no other request of the same group is or will be handled until this request is completed (which provides ordering), the delivery service appends the ordered action to recepitents' message queues one by one. Finally, before releasing the lock, the delivery service pops and attach all new ordered actions of that group in the sender's message queue. This is also why we could not achieve sealed sender for ordered actions. (We use the lock on the entire delivery service state for now, and in future we will work on more granular locks to improve efficiency).

The client, after receiving the acknowledge response, see if there is any new preceding ordered actions. If so, the client should clear the pending commit and process the new ordered actions one by one (and safely discard rejected ones), and finally its own new one (and prompt the user to try again in case of failing). If there is no new preceding ordered actions, the client can just proceed to merge their new commit.

Note that message queues are ordered, and websocket used in Client-Server communications ensure ordering as well, so any numbering is not necessary.

## Denial of Service Considerations

As discussed in [Chapter 3](./3-designing-our-ds.md), epoch number-based conflict resolution is susceptible to malformed actions. With DS-side ordering, when there is any malformed ordered actions either submitted by dishonest clients or was generated based on old group states, honest clients will be able to reject them without any consequences, and the sender of a failed action will can be well-informed. 

Sending back a list of pending ordered actions, while more expensive, is more beneficial than the delivery service (conseratively) selectively accepting ordered actions in general (for example by using epoch or by rejecting when the sender's message queue is not empty).

A malicious client that sends many malformed ordered actions will not block any resources in the former, but can cause DoS for others in the latter. Similarly, if two clients submit conflicting ordered actions (e.g. kicking the same user) but the first (after ordering) fails, all clients will proceed to accept the second ordered action, and the client of the first one will be prompted to sync and reattempt if necessary.

## Implementation Considerations

### Per-Group Locking

The delivery service uses a `DashMap` (a concurrent hash map) to store the state for each group separately. When handling an ordered action for a group, it first obtains a lock on the entry for that specific group in the `DashMap`. This ensures that no other request for the same group will be handled concurrently, providing a per-group ordering guarantee. This is more granular and efficient than using a single global lock over the entire delivery service state.

### Appending and Relaying Actions

Once the lock is obtained, the delivery service appends the new ordered action to the message queue for each recipient in that group. Before releasing the lock, it also collects all new ordered actions for that group that the sender hasn't seen yet, and attaches them to the response sent back to the sender. This is why sealed sender is not possible for ordered actions.

### Client-Side Handling

When the client receives the response, it checks for any new preceding ordered actions. If there are any, the client:

1. Clears its pending commit.
2. Processes the new ordered actions one by one, safely discarding any that are invalid.
3. Finally, processes its own new action. If this fails, it prompts the user to retry.

If there are no new preceding ordered actions, the client can simply proceed to merge its new commit.

### Garbage Collection

To avoid the message queues growing unbounded, the delivery service performs garbage collection. For each message, it maintains a list of recipients who haven't retrieved it yet. When a client retrieves a message, it is removed from this unretrieved recipients list. Once this list becomes empty (i.e., all intended recipients have retrieved the message), the message is deleted from the delivery service.
