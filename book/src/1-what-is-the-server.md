# What is "The Server"?

Recall that, at a high-level a chat app's architecture looks something like this

```
[Alice]  <--->  [Server]  <--->  [Bob]
```

In other words, the server facilitates communication between Alice and Bob. But, to build applications, this is too high-level. Indeed, the [MLS Architecture spec](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-general-setting) refines this a bit, it splits the service provider's functionality into two services:

1. an *Authentication Service*; and
2. a *Delivery Service*.

### What is an Authentication Service?

The authentication service serves the role of an [*Identity Provider*](https://en.wikipedia.org/wiki/Identity_provider), it is a *trusted* service that affirms identity. At a high-level, we can think of an identity provider as a mapping between public user identifiers (like usernames or phone numbers) and public keys. Real-world identity providers typically do more stuff; if you know the full-form of [SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) you know what I am talking about; otherwise, forget it, it doesn't matter here. For us, the authentication service is just a mapping between usernames and public keys.

This service is the *root of trust*, if an adversary can control this service they can update the public key for Alice and impersonate her. In practice, it is *very hard* to build this service: you need to deal with validating identities (some services validate via email), account recovery, and all that other stuff. But, as mentioned above, for a research project, we can ignore all that complexity. But I will that if I wanted to deploy this, I would probably piggyback-off some existing identity provider like Discord, GitHub, Facebook, or Google; which of course comes with some privacy costs.

In [Chapter 2](./3-designing-our-as.md) we discuss how we designed our simple authentication service.
The authentication service is implemented in the `authentication_service` module. It exposes APIs to register users with their credential (public key) and retrieve credentials for users. The service stores the user-to-credential mapping in a `DashMap` called `credential_entries`. 

### What is a Delivery Service?

The delivery service does the actual forwarding of messages. It maintains *sessions* with *user devices*, checks if a message can be forwarded to some device, and if so forwards it to the device.

This service is *less trusted* because it never sees messages in the clear, and since we trust the authentication service and cross-check important messages against it, the delivery service cannot do funky stuff like spoofing messages; however, it can still drop messages and thus deny service to users.

In [Chapter 3](./3-designing-our-ds.md) we discuss how we designed our delivery service and the inherent tradeoffs.
