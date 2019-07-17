=============
ECIES Tunnels
=============

.. meta::
    :author: chisana
    :created: 2019-07-04
    :thread: http://zzz.i2p/topics/2737
    :lastupdated: 2019-07-16
    :status: Draft

.. contents::

Overview
========

This document is a specification proposal for changes to Tunnel encryption and message processing
using crypto primitives introduced by [Prop144]_: ECIES-X25519-AEAD-Ratchet.

For the purposes of transitioning the network from ElGamal + AES256 to ECIES + ChaCha20,
tunnels with mixed ElGamal and ECIES routers are necessary.

Specifications for how to handle mixed tunnel hops are provided.

No changes will be made to the format, processing, or encryption of ElGamal hops.

All ElGamal routers are treated as though running without changes from this document.

The proposal is split into two sections:

- ECIES for Tunnel Building
- ECIES for Tunnel Layer Encryption

If necessary, the proposal can be split into independent proposals for separate analysis and adoption.

Cryptographic Primitives
------------------------

- ChaCha20(msg, nonce, key) - as in [RFC-7539]_
- ChaCha20Poly1305(msg, nonce, AD, key) - as in [NTCP2]_ and [ECIES-X25519]_
- X25519(privateKey, publicKey) - as in [NTCP2]_ and [ECIES-X25519]_
- HKDF(rootKey, sharedSecret, CONTEXT, keylen) - as in [NTCP2]_ and [ECIES-X25519]_
- Blowfish(msg, key) - used only for ECIES-only tunnel nonce encryption, sixteen rounds cipher mode

ECIES for Tunnel Building
=========================

Goals
-----

Replace ElGamal + AES256/CBC with ECIES primitives for tunnel BuildRequestRecords and BuildReplyRecords.

Tunnel Request Records for ECIES Hops
-------------------------------------

Request Record Spec Unencrypted (ElGamal)
`````````````````````````````````````````

.. raw:: html

  {% highlight lang='dataspec' %}

bytes     0-3: tunnel ID to receive messages as, nonzero
  bytes    4-35: local router identity hash
  bytes   36-39: next tunnel ID, nonzero
  bytes   40-71: next router identity hash
  bytes  72-103: AES-256 tunnel layer key
  bytes 104-135: AES-256 tunnel IV key
  bytes 136-167: AES-256 reply key
  bytes 168-183: AES-256 reply IV
  byte      184: flags
  bytes 185-188: request time (in hours since the epoch, rounded down)
  bytes 189-192: next message ID
  bytes 193-221: uninterpreted / random padding
  bytes 222-253: Sha256 of the preceding data

{% endhighlight %}

Request Record Spec Unencrypted (ECIES)
```````````````````````````````````````

.. raw:: html

  {% highlight lang='dataspec' %}

bytes     0-3: tunnel ID to receive messages as, nonzero
  bytes    4-35: local router identity hash
  bytes   36-39: next tunnel ID, nonzero
  bytes   40-71: next router identity hash
  byte       72: flags
  bytes   73-76: request time (in hours since the epoch, rounded down)
  bytes   77-80: next message ID

{% endhighlight %}

Request Record Spec Encrypted (ECIES)
`````````````````````````````````````

.. raw:: html

  {% highlight lang='dataspec' %}

bytes    0-15: hop's truncated identity hash
  bytes   16-47: sender's ephemeral public key
  bytes  48-128: ChaChaPoly AEAD encrypted build request record
  bytes 129-511: Random padding
  bytes 512-527: Poly1305 MAC

{% endhighlight %}

After full transition to ECIES records, bytes 129-527 can be a range of included padding.

Random padding will be formatted using the Padding block structure from [ECIES-X25519]_ and [NTCP2]_.

Flag Changes for Mixed Tunnels
``````````````````````````````

.. raw:: html

  {% highlight lang='dataspec' %}

Bit order: 76543210 (bit 7 is MSB)
  bit 7: if set, allow messages from anyone
  bit 6: if set, allow messages to anyone, and send the reply to the
         specified next hop in a Tunnel Build Reply Message
  bit 5: if set, ChaCha20 reply encryption selected (ECIES build record),
         also indicates next hop is ECIES
         AES256/CBC (ElGamal) otherwise
  bit 4: if set, only ECIES hops in the tunnel, use Blowfish+ChaCha20 layer encryption
  bits 3-0: Undefined, must set to 0 for compatibility with future options

{% endhighlight %}

Tunnel Reply Records for ECIES
------------------------------

Reply Record Spec Unencrypted (ECIES)
`````````````````````````````````````

.. raw:: html

  {% highlight lang='dataspec' %}

bytes      0: reply byte

{% endhighlight %}

Reply flags for ECIES reply records should use the following values to avoid fingerprinting:

- 0x00 (accept)
- 30 (TUNNEL_REJECT_BANDWIDTH)

Reply Record Spec Encrypted (ECIES)
```````````````````````````````````

.. raw:: html

  {% highlight lang='dataspec' %}

bytes       0: ChaChaPoly AEAD encrypted build reply record
  bytes   1-511: Random padding
  bytes 512-527: Poly1305 MAC

{% endhighlight %}

After full transition to ECIES records, ranged padding rules are the same as for request records.

Symmetric Encryption of Asymmetrically Encrypted Records
--------------------------------------------------------

Mixed tunnels are allowed, and necessary, for full network transition from ElGamal to ECIES.
During the transitionary period, a statistically increasing number of routers will be keyed under ECIES keys.

Symmetric cryptography preprocessing will run in the same way:

- "encryption":
  * cipher run in decryption mode
  * request records preemptively decrypted in preprocessing (concealing encrypted request records)
- "decryption":
  * cipher run in encryption mode
  * request records encrypted (revealing next plaintext request record) by participant hops
- ChaCha20 does not have "modes", so it is simply run three times:
  * once in preprocessing
  * once by the hop
  * once on final reply processing

When mixed routers are hops in the same tunnel, and the current hop is ECIES,
it will check if reply encryption flag is set (indicating ChaCha20).

If the current hop is an ECIES hop, and ChaCha20 reply encryption is selected,
the reply key is used to ChaCha20 "decrypt" its reply and other records.

If the current hop is an ElGamal hop, the reply encryption bit is ignored,
and the reply key is used to AES256/CBC "decrypt" its reply and other records.

This means later hops in the tunnel are preprocessed using a mix of ChaCha20
and AES256/CBC, using the reply key of preceding hops.

On the reply path, the endpoint (sender) will need to undo the [Multiple-Encryption]_, using each hop's reply key.

As a clarifying example, let's look at an outbound tunnel w/ ECIES surrounded by ElGamal:

- Sender (OBGW) -> ElGamal (H1) -> ECIES (H2) -> ElGamal (H3)

All records are in their encrypted state (using ElGamal or ECIES).

AES256/CBC cipher, when used, is still used for each record, without chaining across multiple records.

The request records are preprocessed by the Sender (OBGW):

- H3's record is "encrypted" using:
  * H2's reply key (AES256/CBC)
  * H1's reply key (AES256/CBC)
- H2's record is "encrypted" using:
  * H1's reply key (AES256/CBC)
- H1's record goes out without symmetric encryption

Only H2 checks the reply encryption flag, and sees its followed by AES256/CBC.

H3 checks the flags, sees it is an OBEP (bit 6 set), and ignores the reply encryption bit.

After being processed by each hop, the records are in a "decrypted" state:

- H3's record is "decrypted" using:
  * H3's reply key (AES256/CBC)
- H2's record is "decrypted" using:
  * H3's reply key (AES256/CBC)
  * H2's reply key (AES256/CBC)
- H1's record is "decrypted" using:
  * H3's reply key (AES256/CBC)
  * H2's reply key (AES256/CBC)
  * H1's reply key (AES256/CBC)

When there are no inbound tunnels at startup, the Sender (IBEP) postprocesses the reply:

- H3's record is "encrypted" using:
  * H3's reply key (AES256/CBC)
- H2's record is "encrypted" using:
  * H3's reply key (AES256/CBC)
  * H2's reply key (AES256/CBC)
- H1's record is "encrypted" using:
  * H3's reply key (AES256/CBC)
  * H2's reply key (AES256/CBC)
  * H1's reply key (AES256/CBC)

If H3 (OBEP) is an ECIES hop, it checks the reply encryption flag for
ChaCha20 (bit 5 set) or AES256/CBC (bit 5 unset).

H2 would also see that the reply encryption flag is set, and "decrypt" its reply
and other records using ChaCha20.

So our example changes to the following hops:

- Sender (OBGW) -> ElGamal (H1) -> ECIES (H2) -> ECIES (H3)

The request records are preprocessed by the Sender (OBGW):

- H3's record is "encrypted" using:
  * H2's reply key (ChaCha20)
  * H1's reply key (AES256/CBC)
- H2's record is "encrypted" using:
  * H1's reply key (AES256/CBC)
- H1's record goes out without symmetric encryption

After being processed by each hop, the records are in a "decrypted" state:

- H3's record is "decrypted" using:
  * H3's reply key (ChaCha20)
- H2's record is "decrypted" using:
  * H3's reply key (ChaCha20)
  * H2's reply key (ChaCha20)
- H1's record is "decrypted" using:
  * H3's reply key (ChaCha20)
  * H2's reply key (ChaCha20)
  * H1's reply key (AES256/CBC)

When there are no inbound tunnels at startup, the Sender (IBEP) postprocesses the reply:

- H3's record is "encrypted" using:
  * H3's reply key (ChaCha20)
- H2's record is "encrypted" using:
  * H3's reply key (ChaCha20)
  * H2's reply key (ChaCha20)
- H1's record is "encrypted" using:
  * H3's reply key (ChaCha20)
  * H2's reply key (ChaCha20)
  * H1's reply key (AES256/CBC)

Request Record Key, Reply Key, Tunnel Layer Key, and IV Key KDF (ECIES)
---------------------------------------------------------------------------------

The ``recordKey`` takes the place of the product of the ElGamal exchange. It is used
to AEAD encrypt request and reply records for ECIES hops.

Below is a description of how to derive the keys previously transmitted in request records.

.. raw:: html

  {% highlight lang='dataspec' %}

// Sender generates an X25519 ephemeral keypair per VTBM (sesk, sepk)
  sesk = GENERATE_PRIVATE()
  sepk = DERIVE_PUBLIC(sesk)

  // Each hop's X25519 static keypair (hesk, hepk), generated for NTCP2 RouterInfos and LeaseSet2s
  hesk = GENERATE_PRIVATE()
  hepk = DERIVE_PUBLIC(hesk)

  // Sender performs an X25519 DH with Hop's static public key.
  // Each Hop, finds the record w/ their truncated identity hash,
  // and extracts the Sender's ephemeral key preceding the encrypted record.
  sharedSecret = DH(sesk, hepk) = DH(hesk, sepk)

  // Derive a root key from the Sha256 of Sender's ephemeral key and Hop's full identity hash
  rootKey = Sha256(sepk || hop_ident_hash)

  keydata = HKDF(rootKey, sharedSecret, "ECIESRequestRcrd", 96)
  rootKey = keydata[0:31]  // update the root key
  recordKey = keydata[32:63]  // AEAD key for Request Record encryption
  replyKey = keydata[64:95]  // Hop reply key

  keydata = HKDF(rootKey, sharedSecret, "TunnelLayerIVKey", 96)
  rootKey = keydata[0:31]  // update the root key
  layerKey = keydata[32:63]  // Tunnel layer key
  IVKey = keydata[64:96]  // Tunnel IV/nonce key

{% endhighlight %}

``replyKey``, ``layerKey`` and ``IVKey`` must still be included inside ElGamal records,
and can be generated randomly. For ElGamal, the ``recordKey`` is just the result of ElGamal multiplication.

Keys are omitted from ECIES records (since they can be derived at the hop).

Request Record Preprocessing for ECIES Hops
-------------------------------------------

.. raw:: html

  {% highlight lang='dataspec' %}

// See record key KDF for key generation
  (ciphertext, mac) = ChaCha20-Poly1305(msg = unencrypted record, nonce = 0, AD = Sha256(recordKey), key = recordKey)

  // For subsequent records past the initial hop
  // nonce = one + zero-indexed order of record in the TunnelBuildMessage
  symCiphertext = ChaCha20(msg = ciphertext \|\| MAC, nonce, key = replyKey of preceding hop)

{% endhighlight %}

Request Record Encryption from ElGamal Tunnel Creators
------------------------------------------------------

No changes are made for how ElGamal routers preprocess and encrypt request records.

This means ECIES hops will behave like ElGamal hops in ElGamal created tunnels.

For ECIES hops to detect ElGamal tunnel creators, trial-decryption is needed.

It will be necessary to first try decrypting the request record as though it came from an ECIES router.

If trial-decryption fails, attempt decryption as though from an ElGamal router.

If the record includes expected fields (keys + IV, flags, etc, and valid Sha256 of preceding data), ElGamal decryption was succesful.

If ElGamal decryption fails, drop the message without reply, or forwarding to next hop.

Reply Record Encryption for ECIES Hops
--------------------------------------

.. raw:: html

  {% highlight lang='dataspec' %}

// See reply key KDF for key generation
  (ciphertext, MAC) = ChaCha20-Poly1305(msg = reply byte, nonce = 0, AD = Sha256(replyKey), key = replyKey)

  If ChaCha20 reply encryption is set in the request record (flags bit 5 set):

  // Advance the nonce to avoid security issues, see [RFC-7539-S4]_ Security Considerations.
  // nonce = one + zero-indexed order of record in the TunnelBuildMessage
  symCiphertext = ChaCha20(msg = ciphertext || MAC || random padding, nonce, key = replyKey)

  // Other request/reply record encryption
  // Advance the nonce to avoid security issues, see [RFC-7539-S4]_ Security Considerations.
  // nonce = one + number of records + zero-indexed order of record in the TunnelBuildMessage
  symCiphertext = ChaCha20(msg = multiple encrypted record, nonce, key = replyKey)

  If AES256/CBC reply encryption is set in the request record (flag bit 5 unset):

  // Other request/reply record encryption
  msg = multiple encrypted record
  key = replyKey
  IV = Sha256(replyKey || hop static public key)
  symCiphertext = AES256-CBC-Encrypt(msg, key, IV)

{% endhighlight %}

While mixed tunnels are used, reply records are the same size, though the format is different.

After full transition to ECIES, random padding (bytes 49-527) can be a range of included padding.

When ranged padding is used, first two bytes of padding can be used to indicate padding length.
For symmetric encryption by other hops, it's necessary to know full record length (w/ padding) without asymetric decryption.

Reply Record Encryption for ElGamal Hops
----------------------------------------

There are no changes for how ElGamal hops encrypt their replies.

Security Analysis for ECIES + ChaCha20 Tunnel Build Encryption
--------------------------------------------------------------

ElGamal does not provide forward-secrecy for Tunnel Build Messages.

AES256/CBC is in slightly better standing, only being vulnerable to a theoretical weakening from a
known plaintext `biclique` attack.

The only known practical attack against AES256/CBC is a padding oracle attack, when the IV is known to the attacker.

An attacker would need to break the next hop's ElGamal encryption to gain the AES256/CBC key info (reply key and IV).

ElGamal is significantly more CPU-intensive than ECIES, leading to potential resource exhaustion.

ECIES, used with new ephemeral keys per-BuildRequestRecord or VariableTunnelBuildMessage, provides forward-secrecy.

ChaCha20Poly1305 provides AEAD encryption, allowing the recipient to verify message integrity before attempting decryption.

ECIES Tunnel Layer Encryption
=============================

Goals
-----

The goal of this section is to replace AES256/ECB+CBC with Blowfish+ChaCha20 for established tunnel IV and layer encryption.

Established Tunnel Message Processing
-------------------------------------

This section describes changes to:

- Outbound and Inbound Gateway preprocessing + encryption
- Participant encryption + postprocessing
- Outbound and Inbound Endpoint encryption + postprocessing

Changes are for mixed tunnels, and ElGamal hops are considered unchanged.

For an overview of current tunnel message processing, see the [Tunnel-Implementation]_ spec.

Only changes for ECIES gateways + hops are discussed.

No changes are considered for mixed tunnel with ElGamal routers, until a safe protocol can be devised
for converting a 128-bit AES IV to a 64-bit ChaCha20 nonce. Bloom filters guarantee uniqueness
for the full IV, but the first half of unique IVs could be identical.

This means ECIES routers will use current AES tunnel layer encryption whenever ElGamal hops
are present in the tunnel.

See section on build request records for ECIES hop detection of ElGamal tunnel creators.

Gateway and Tunnel Creator Message Processing
---------------------------------------------

Gateways will fragment and bundle messages in the same way.

AEAD frames (including the MAC) can be split across fragments, but any dropped
fragments will result in failed AEAD decryption (failed MAC verification).

Gateway Preprocessing & Encryption
----------------------------------

When tunnels are ECIES-only, gateways will generate 64-bit nonces for use by ECIES hops.

Inbound tunnels:

- Encrypt the IV and tunnel message(s) using ChaCha20
- Use 8-byte ``tunnelNonce`` given the lifetime of tunnels
- Destroy tunnel before 2^(64/2 - 1) messages: 2^31 = 2,147,483,648

  - Nonce limit in place to avoid Sweet32 attack on Blowfish
  - Nonce limit unlikely to ever be reached, given this would be ~3,579,139 msgs/second for 10 minute tunnels
  - Nonce cannot be truncated. For shorter nonce, a different method must be used with smaller state space.

The tunnel's Inbound Gateway (IBGW), processes messages received from another tunnel's Outbound Endpoint (OBEP).

At this point, the outermost message layer is encrypted using point-to-point transport encryption.
The I2NP message headers are visible, at the tunnel layer, to the OBEP and IBGW.
The inner I2NP messsages are wrapped in Garlic cloves, encrypted using end-to-end session encryption.

The IBGW preprocesses the messages into the appropriately formatted tunnel messages, and encrypts as following:

.. raw:: html

  {% highlight lang='dataspec' %}

// For ECIES-only tunnels
  // IBGW generates a random nonce, ensuring no collision in its Bloom filter
  tunnelNonce = Random(len = 64-bits)
  // IBGW ChaCha20 "encrypts" the preprocessed tunnel messages with its tunnelNonce and layerKey
  encMsg = ChaCha20(msg = tunnel msg(s), nonce = tunnelNonce, key = layerKey)

  // For mixed tunnels w/ ElGamal hops (unchanged)
  encIV = AES256/ECB-Encrypt(msg = prev. encIV, key = hop's IVKey)
  encMsg = AES256/CBC-Encrypt(msg = tunnel msg(s), IV = encIV, key = hop's layerKey)
  encIV2 = AES256/ECB-Encrypt(msg = encIV, key = hop's IVKey)

  {% endhighlight %}

  Tunnel message format will slightly change, using an 8-byte nonce instead of a 16-byte IV.
  The rest of the format is unchanged.

  Outbound tunnels:

  For outbound tunnels, the tunnel creator is the Outbound Gateway (OBGW).

  On outbound tunnel creation, Variable Tunnel Build Messages are created,
  preprocessed (iteratively decrypted), and sent out to the first potential hop in the tunnel.

  Replies are directed to a zero-hop or existing inbound tunnel's IBGW.

  - Iteratively decrypt tunnel messages

    - ECIES-only tunnel hops will encrypt using Blowfish+ChaCha20
    - mixed-tunnel hops will encrypt using AES256/ECB+CBC

  - Use the same rules for IV and layer nonces as Inbound tunnels

.. raw:: html

  {% highlight lang='dataspec' %}


// For ECIES-only tunnel hops
  // For each hop, Blowfish-Decrypt the previous tunnelNonce with the current hop's Blowfish keys
  tunnelNonce = Blowfish-Decrypt(msg = prev. tunnelNonce, key = IVKey)
  // For each hop, ChaCha20 "decrypt" the tunnel message with the current hop's tunnelNonce and layerKey
  decMsg = ChaCha20(msg = tunnel msg(s), nonce = tunnelNonce, key = hop's layerKey)

  // For ElGamal hops (unchanged)
  // Tunnel creator generates a random IV
  // For each hop, decrypt the IV and tunnel message(s)
  // For the first hop, the previous decrypted IV will be the randomly generated IV
  decIV = AES256/ECB-Decrypt(msg = prev. decIV, key = hop's IVKey)
  decMsg = AES256/CBC-Decrypt(msg = tunnel msg(s), IV = decIV, key = hop's layerKey)
  decIV2 = AES256/ECB-Decrypt(msg = decIV, key = hop's IVKey)

{% endhighlight %}

Participant Processing
----------------------

Participants will track seen messages in the same way, using decaying Bloom filters.

IV double-encryption is no longer necessary for ECIES hops,
since there are no padding-oracle attacks against ChaCha20.

ChaCha20 hops will encrypt the received nonce to prevent confirmation attacks between prior and later hops,
i.e. colluding, non-consecutive hops being able to tell they belong to the same tunnel.

IV double-encryption will still be used for mixed-tunnel hops, since they are considered unchanged.

To validate received ``tunnelNonce``, the participant checks against its Bloom filter for duplicates.

After validation, the participant:

- Blowfish encrypts the ``tunnelNonce`` with its ``IVKey``
- Uses the encrypted ``tunnelNonce`` & its ``layerKey`` to ChaCha20 encrypt the tunnel message(s)
- Sends the tuple {``tunnelId``, encrypted ``tunnelNonce``, ciphertext} to the next hop.

.. raw:: html

  {% highlight lang='dataspec' %}

// For ECIES-only tunnel hops
  // For verification, tunnel participant should check Bloom filter for received nonce uniqueness
  // After verification, Blowfish encrypt the tunnelNonce with the hop's IVKey
  tunnelNonce = Blowfish-Encrypt(msg = received tunnelNonce, key = IVKey)
  encMsg = ChaCha20(msg = received message, nonce = tunnelNonce, key = layerKey)

  // For ElGamal hops (unchanged)
  currentIV = AES256/ECB-Encrypt(msg = received IV, key = hop's IVKey)
  encMsg = AES256/CBC-Encrypt(msg = tunnel msg(s), IV = currentIV, key = hop's layerKey)
  nextIV = AES256/ECB-Encrypt(msg = currentIV, key = hop's IVKey)

{% endhighlight %}

Inbound Endpoint Processing
---------------------------

Inbound Endpoints will check the composition of their tunnel hops (ECIES or ElGamal).

Mixed tunnels are considered unchanged for tunnel layer encryption.

For ECIES-only tunnels, the following scheme will be used:

- Validate the received ``tunnelNonce`` against the Bloom filter
- ChaCha20 decrypt the encrypted data using the received ``tunnelNonce`` & the hop's ``layerKey``
- Blowfish decrypt the ``tunnelNonce`` using the hop's ``IVKey`` to get the preceding ``tunnelNonce``
- ChaCha20 decrypt the encrypted data using the decrypted ``tunnelNonce`` & the preceding hop's ``layerKey``
- Repeat for each hop in the tunnel, back to the IBGW

.. raw:: html

  {% highlight lang='dataspec' %}

// For ECIES-only tunnel hops
  // Repeat for each hop in the tunnel back to the IBGW
  // Replace the received tunnelNonce w/ the prior round hop's decrypted tunnelNonce for subsequent hops
  tunnelNonce = Blowfish-Decrypt(msg = received tunnelNonce, key = IVKey)
  decMsg(s) = ChaCha20(msg = encrypted layer message(s), nonce = tunnelNonce, key = layerKey)

  // For mixed tunnel hops (unchanged)
  // Repeat for each hop in the tunnel back to the IBGW
  // Replace the received IV w/ the prior round hop's double-decrypted IV for subsequent hops
  decIV = AES256/ECB(msg = received IV, key = IVKey)
  decMsg = AES256/CBC(msg = tunnel msg(s), IV = decIV, key = layerKey)
  decIV2 = AES256/ECB(msg = decIV, key = IVKey)

{% endhighlight %}

Security Analysis for Blowfish+ChaCha20 Tunnel Layer Encryption
------------------------------------------------------

Switching from AES256/ECB to ChaCha20 has a number of advantages, and new security considerations.

The biggest security considerations to account for, are that ChaCha20 nonces must be unique per-message,
for the life of the key being used, and Blowfish is susceptible to Sweet32 birthday attacks.

Failing to use unique nonces with the same key on different messages breaks ChaCha20.

Nonce uniqueness is main reason for using an Blowfish, see [RFC-7539-S4]_.

Simple counters cannot be used, since they require syncing for proper decryption.
Syncing the counter can't be guaranteed at the IBEP, without further changes to tunnel protocols.

Blowfish is only used for nonce encryption to guarantee unique nonces, and prevent non-consecutive
hops in the same tunnel from colluding to know they are in the same tunnel.

The tunnel lifetime of ten minutes and nonce limit of 2^31 messages guarantees that Sweet32 attacks
are ineffective against Blowfish. Exceeding the limit would require over ~3,579,139 messages/second in each tunnel.

Even if 2^31 messages proves to not be a strict enough limit, we can safely reduce the limit by another power of two,
without ever realistically reaching the limit.

Even if a Sweet32 attack were successful, an attacker would only gain access to the ``tunnelNonce``
for the colliding message, which doesn't break the ChaCha20 encryption. Non-consecutive hops
would only be able to confirm they are participants in the same tunnel.

The biggest security advantage is that there are no confirmation or oracle attacks against ChaCha20.

There are chosen/known-plaintext attacks against AES256/ECB, when the key is reused (as in tunnel layer encryption).

It is unlikely the chosen-plaintext attack can be used to recover double-encrypted IVs, since it requires at least two blocks
to be encrypted, and a single pass of the cipher.

An attack confirming a chosen plaintext IV is much more likely, but still unclear if it would be successful given
double-encryption.

The chosen-plaintext producing a recovered IV cannot be used to perform
a padding-oracle attack against AES256/CBC layer encryption, since duplicate IVs are rejected.

Tunnel Message Overhead for ECIES
=================================

Wrapped I2NP message overhead:

- I2NP Block header: 3 (block type + size) + 9 (I2NP message header) = 12
- New Session Message:

  - 25 (min payload len) + 16 (MAC) = 41
  - 32 (one-time key) + 40 (ephemeral section) + 16 (MAC) + 41 (min payload) = 129 unbound
  - 88 (unbound) + 32 (static section) + 16 (MAC) + 41 (min payload) = 177 bound

- Existing Message: 8 (session tag) + payload len + 16 (MAC) = 24 + payload len

- New session:

  - 12 (I2NP) + 129 (unbound) = 141 + payload
  - 12 (I2NP + 177 (bound) = 189 + payload

- Existing Session: 12 (I2NP) + 24 = 36 + payload
- Build Request Record: 528 (ElGamal, mixed tunnels)
- Build Request Reply: 528 (ElGamal, mixed tunnels)

Tunnel message overhead:

Wrapped I2NP message overhead:

- I2NP Block header: 3 (block type + size) + 9 (I2NP message header) = 12
- New Session Message:

  - 25 (min payload len) + 16 (MAC) = 41
  - 32 (one-time key) + 40 (ephemeral section) + 16 (MAC) + 41 (min payload) = 129 unbound
  - 88 (unbound) + 32 (static section) + 16 (MAC) + 41 (min payload) = 177 bound

- Existing Message: 8 (session tag) + payload len + 16 (MAC) = 24 + payload len

- New session:

  - 12 (I2NP) + 129 (unbound) = 141 + payload
  - 12 (I2NP + 177 (bound) = 189 + payload

- Existing Session: 12 (I2NP) + 24 = 36 + payload
- Build Request Record: 528 (ElGamal, mixed tunnels)
- Build Request Reply: 528 (ElGamal, mixed tunnels)

Tunnel message overhead:

Tunnel layer keys, IV keys, and reply keys no longer need to be transmitted in ECIES BuildRequest Records.
Unused space claimed by random padding and the trailing 16 byte Poly1305 MAC.

ECIES session messages will be wrapped in I2NP Data messages, surrounded by a Garlic Clove,
and fragmented in Tunnel Data messages like any other message.

Dropped fragments will result in AEAD decryption failure (fails MAC verification),
resulting in the entire message being dropped.

References
==========

.. [ECIES-X25519]
   {{ proposal_url('144') }}

.. [NTCP2]
   https://geti2p.net/spec/ntcp2

.. [Tunnel-Implementation]
   https://geti2p.net/en/docs/tunnels/implementation

.. [Multiple-Encryption]
   https://en.wikipedia.org/wiki/Multiple_encryption

.. [RFC-7539]
   https://tools.ietf.org/html/rfc7539

.. [RFC-7539-S4]
   https://tools.ietf.org/html/rfc7539#section-4

.. [SplitMix64]
   http://xoshiro.di.unimi.it/splitmix64.c
