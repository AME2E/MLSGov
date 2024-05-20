# Designing our Authentication Service

As mentioned above, the authentication service is a mapping between usernames and public keys. In MLS terms, we are going to define a user by a [`Credential`](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-credentials) which, for us, is an Ed25519 Public Key (think Ed25519 SSH public key.)

Since we are not building for production, we build a simple `/v1/user/register` API that takes a (username, publickey) pair and stores it in a hashmap with the username as the primary key. (The hashmap is saved to disk via `confy`.) And follow that up with a `/v1/user/retrieve` API that takes a username and returns the associated public key.

In the future, we can make register take a password, and add a `/v1/user/update` API that allows a user to update their public key by supplying the password.

The authentication service is implemented in `authentication_service/src/main.rs`. It uses the `AuthServiceState` struct defined in `corelib/src/servers_api/as_struct.rs` to store the mapping between user names and their credential entry (credential + verification key). 

The key APIs are:

- `UserRegisterForAS`: Allows a user to register with the AS by providing their credential and verification key. This is stored in the `credential_entries` map.

- `UserCredentialLookup`: Allows looking up the credential for a given user name.

- `UserSyncCredentials`: Syncs all credentials stored in the AS to the requesting client.

The AS listens for incoming WebSocket connections. When it receives an `OnWireMessage`, it passes it to `handle_onwire_msg_as_local` defined in `corelib/src/servers_api/mod.rs` to process it and generate a response.
