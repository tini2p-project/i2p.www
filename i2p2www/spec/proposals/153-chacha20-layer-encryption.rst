==============================
ChaCha Tunnel Layer Encryption
==============================

.. meta::
    :author: chisana
    :created: 2019-08-04
    :thread: http://zzz.i2p/topics/2753
    :lastupdated: 2019-08-05
    :status: Draft

.. contents::

Overview
========

This proposal builds on and requires the changes from proposal 152: ECIES Tunnels.

Only tunnels built through hops supporting the BuildRequestRecord format for ECIES-X25519
tunnels can implement this specification.

This specification requires the Tunnel Build Options format for indicating
tunnel layer encryption type, and transmitting layer AEAD keys.

Goals
-----

The goals of this proposal are to:

- Replace AES256/ECB+CBC with ChaCha20 for established tunnel IV and layer encryption
- Use ChaCha20-Poly1305 for inter-hop AEAD protection
- Be undetectable from existing tunnel layer encryption by non-tunnel participants
- Make no changes to overall tunnel message length

Established Tunnel Message Processing
-------------------------------------

This section describes changes to:

- Outbound and Inbound Gateway preprocessing + encryption
- Participant encryption + postprocessing
- Outbound and Inbound Endpoint encryption + postprocessing

For an overview of current tunnel message processing, see the [Tunnel-Implementation]_ spec.

Only changes for routers supporting ChaCha20 layer encryption are discussed.

No changes are considered for mixed tunnel with AES layer encryption, until a safe protocol can be devised
for converting a 128-bit AES IV to a 64-bit ChaCha20 nonce. Bloom filters guarantee uniqueness
for the full IV, but the first half of unique IVs could be identical.

This means layer encryption must be uniform for all hops in the tunnel, and established using
tunnel build options during the tunnel creation process.

All gateways and tunnel participants will need to maintain a Bloom filter for validating the two independent nonces.

AEAD Encryption of Hop-to-Hop Messages
--------------------------------------

An additional unique ``AEADKey`` will need to be generated for each pair of consecutive hops.
This key will be used by consecutive hops to ChaCha20-Poly1305 encrypt and decrypt the
inner ChaCha20 encrypted tunnel message.

Tunnel messages will need to reduce the length of the inner encrypted frame by 16 bytes to
accommodate the Poly1305 MAC.

AEAD cannot be used on the messages directly, since iterative decryption is needed by outbound tunnels.
Iterative decryption can only be achieved, in the way it's used now, using ChaCha20 without AEAD.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  |    Tunnel ID      |   tunnelNonce     |
  +----+----+----+----+----+----+----+----+
  | tunnelNonce cont. |    randNonce      |
  +----+----+----+----+----+----+----+----+
  |  randNonce cont.  |                   |
  +----+----+----+----+                   +
  |                                       |
  +           Encrypted Data              +
  ~                                       ~
  |                                       |
  +                   +----+----+----+----+
  |                   |    Poly1305 MAC   |
  +----+----+----+----+                   +
  |                                       |
  +                   +----+----+----+----+
  |                   |
  +----+----+----+----+

  Tunnel ID :: `TunnelId`
         4 bytes
         the ID of the next hop

  tunnelNonce ::
         8 bytes
         the tunnel layer nonce

  randNonce ::
         8 bytes
         the tunnel layer nonce encryption nonce

  Encrypted Data ::
         992 bytes
         the encrypted tunnel message

  Poly1305 MAC ::
         16 bytes

  total size: 1028 Bytes
{% endhighlight %}

Inner hops (with preceding and following hops), will have two ``AEADKeys``, one for decrypting
the AEAD layer of the previous hop, and encrypting the AEAD layer to the following hop.

All inner hop participants will thus have 64 additional bytes of key material included in their BuildRequestRecords.

The Outbound Endpoint and Inbound Gateway will only require an additional 32 bytes of keydata,
since they do not tunnel layer encrypt messages between each other.

The Outbound Gateway generates its ``sendKey``, which is the same as the first outbound hop's ``receiveKey``.

The Inbound Endpoint generates its ``receiveKey``, which is the same as the final inbound hop's ``sendKey``.

Inner hops will receive and ``receiveKey`` and ``sendKey`` which will be used to AEAD decrypt
incoming messages and encrypt outgoing messages, respectively.

As an example, in a tunnel with inner hops OBGW, A, B, OBEP:

- A's ``receiveKey`` is the same as the OBGW's ``sendKey``
- B's ``receiveKey`` is the same as A's ``sendKey``
- B's ``sendKey`` is the same as OBEP's ``receiveKey``

Keys are unique to hop pairs, so OBEP's ``receiveKey`` will be different than A's ``receiveKey``,
A's ``sendKey`` different than B's ``sendKey``, etc.

Tunnel Nonces
-------------

The tunnel nonces are used to ensure the security of the layer and AEAD encryption.

The ``tunnelNonce`` is used for layer encryption, and inter-hop AEAD encryption.

The ``randNonce`` is used to encrypt the ``tunnelNonce``, cryptographically randomizing the ``tunnelNonce``.

Randomization is needed for both secure use in the cryptosystem, and hiding the ``tunnelNonce`` value
from non-consecutive, colluding hops.

ChaCha20 and ChaCha20-Poly1305 require unique nonces for each message for the lifetime of the key being used.

Gateway and Tunnel Creator Message Processing
---------------------------------------------

Gateways will fragment and bundle messages in the same way, reserving space after the instructions-fragment
frame for the Poly1305 MAC.

Inner I2NP messages containing AEAD frames (including the MAC) can be split across fragments,
but any dropped fragments will result in failed AEAD decryption (failed MAC verification) at the endpoint.

Gateway Preprocessing & Encryption
----------------------------------

When tunnels support ChaCha20 layer encryption, gateways will generate two 64-bit nonces per message set.

Inbound tunnels:

- Encrypt the IV and tunnel message(s) using ChaCha20
- Use 8-byte ``tunnelNonce`` and ``randNonce`` given the lifetime of tunnels
- Use 8-byte ``randNonce`` for ``tunnelNonce`` encryption
- Destroy tunnel before 2^(64 - 1) - 1 sets of messages: 2^63 - 1 = 9,223,372,036,854,775,807

  - Nonce limit in place to avoid collision of the 64-bit nonces
  - Nonce limit nearly impossible to ever be reached, given this would be over ~15,372,286,728,091,294 msgs/second for 10 minute tunnels

- Tune the Bloom filter based on a reasonable number of expected elements (128 msgs/sec, 1024 msgs/sec? TBD)

The tunnel's Inbound Gateway (IBGW), processes messages received from another tunnel's Outbound Endpoint (OBEP).

At this point, the outermost message layer is encrypted using point-to-point transport encryption.
The I2NP message headers are visible, at the tunnel layer, to the OBEP and IBGW.
The inner I2NP messsages are wrapped in Garlic cloves, encrypted using end-to-end session encryption.

The IBGW preprocesses the messages into the appropriately formatted tunnel messages, and encrypts as following:

.. raw:: html

  {% highlight lang='dataspec' %}

// IBGW generates random nonces, ensuring no collision in its Bloom filter for each nonce
  tunnelNonce = Random(len = 64-bits)
  randNonce = Random(len = 64-bits)
  // IBGW ChaCha20 "encrypts" each of the preprocessed tunnel messages with its tunnelNonce and layerKey
  encMsg = ChaCha20(msg = tunnel msg, nonce = tunnelNonce, key = layerKey)

  // ChaCha20-Poly1305 encrypt each message's encrypted data frame with the tunnelNonce and sendKey
  (encMsg, MAC) = ChaCha20-Poly1305-Encrypt(msg = encMsg, nonce = tunnelNonce, key = sendKey)
{% endhighlight %}

Tunnel message format will slightly change, using two 8-byte nonces instead of a 16-byte IV.
The ``randNonce`` used for encrypting the nonce is appended to the 8-byte ``tunnelNonce``,
and is encrypted by each hop using the encrypted ``tunnelNonce`` and the hop's ``randKey``.

After the message set has be pre-emptively decrypted for each hop, the Outbound Gateway
ChaCha20-Poly1305 AEAD encrypts the ciphertext portion of each tunnel message using
the ``tunnelNonce`` and its ``sendKey``.

Outbound tunnels:

- Iteratively decrypt tunnel messages
- ChaCha20-Poly1305 encrypt preemptively decrypted tunnel message encrypted frames
- Use the same rules for layer nonces as Inbound tunnels
- Generate random nonces once per set of tunnel messages sent

.. raw:: html

  {% highlight lang='dataspec' %}


// For each set of messages, generate unique, random nonces
  tunnelNonce = Random(len = 64-bits)
  randNonce = Random(len = 64-bits)

  // For each hop, ChaCha20 the previous tunnelNonce with the current hop's IV key
  tunnelNonce = ChaCha20(msg = prev. tunnelNonce, nonce = randNonce, key = hop's randKey)

  // For each hop, ChaCha20 "decrypt" the tunnel message with the current hop's tunnelNonce and layerKey
  decMsg = ChaCha20(msg = tunnel msg(s), nonce = tunnelNonce, key = hop's layerKey)

  // For each hop, ChaCha20 "decrypt" the randNonce with the current hop's encrypted tunnelNonce and randKey
  randNonce = ChaCha20(msg = randNonce, nonce = tunnelNonce, key = hop's randKey)

  // After hop processing, ChaCha20-Poly1305 encrypt each tunnel message's "decrypted" data frame with the first hop's encrypted tunnelNonce and receiveKey
  (encMsg, MAC) = ChaCha20-Poly1305-Encrypt(msg = decMsg, nonce = first hop's encrypted tunnelNonce, key = first hop's receiveKey / GW sendKey)
{% endhighlight %}

Participant Processing
----------------------

Participants will track seen messages in the same way, using decaying Bloom filters.

Tunnel nonces will each need to be encrypted once per-hop, to prevent confirmation attacks
by non-consecutive, colluding hops.

Hops will encrypt the received nonce to prevent confirmation attacks between prior and later hops,
i.e. colluding, non-consecutive hops being able to tell they belong to the same tunnel.

To validate received ``tunnelNonce`` and ``randNonce``, participants check each nonce individually
against their Bloom filter for duplicates.

After validation, the participant:

- ChaCha20-Poly1305 decrypts each tunnel message's AEAD ciphertext with the received ``tunnelNonce`` and its ``receiveKey``
- ChaCha20 encrypts the ``tunnelNonce`` with its ``randKey`` and received ``randNonce``
- ChaCha20 encrypts the each tunnel message's encrypted data frame with the encrypted ``tunnelNonce`` and its ``layerKey``
- ChaCha20-Poly1305 encrypts each tunnel message's encrypted data frame the encrypted ``tunnelNonce`` and its ``sendKey``
- ChaCha20 encrypts the ``randNonce`` with its ``randKey`` and encrypted ``tunnelNonce``
- Sends the tuple {``nextTunnelId``, encrypted (``tunnelNonce`` || ``randNonce``), AEAD ciphertext || MAC} to the next hop.

.. raw:: html

  {% highlight lang='dataspec' %}

// For verification, tunnel hops should check Bloom filter for each received nonce's uniqueness
  // After verification, unwrap the AEAD frame(s) byChaCha20-Poly1305 decrypt each tunnel message's encrypted frame
  // with the received tunnelNonce and receiveKey
  encTunMsg = ChaCha20-Poly1305-Decrypt(msg = received encMsg || MAC, nonce = received tunnelNonce, key = receiveKey)

  // ChaCha20 encrypt the tunnelNonce with the randNonce and hop's randKey
  tunnelNonce = ChaCha20(msg = received tunnelNonce, nonce = received randNonce, key = randKey)

  // ChaCha20 encrypt each tunnel message's encrypted data frame with the encrypted tunnelNonce and hop's layerKey
  encMsg = ChaCha20(msg = encTunMsg, nonce = tunnelNonce, key = layerKey)

  // For AEAD protection, also ChaCha20-Poly1305 encrypt each message's encrypted data frame
  // with the encrypted tunnelNonce and the hop's sendKey
  (encMsg, MAC) = ChaCha20-Poly1305-Encrypt(msg = encMsg, nonce = tunnelNonce, key = sendKey)

  // ChaCha20 encrypt the received randNonce with the encrypted tunnelNonce and hop's randKey
  randNonce = ChaCha20(msg = randNonce, nonce = tunnelNonce, key = randKey)
{% endhighlight %}

Inbound Endpoint Processing
---------------------------

For ChaCha20 tunnels, the following scheme will be used to decrypt each tunnel message:

- Validate the received ``tunnelNonce`` and ``randNonce`` independently against its Bloom filter
- ChaCha20-Poly1305 decrypt the encrypted data frame using the received ``tunnelNonce`` and ``receiveKey``
- ChaCha20 decrypt the encrypted data frame using the received ``tunnelNonce`` & the hop's ``layerKey``
- ChaCha20 decrypt the ``randNonce`` using the hop's ``randKey`` and received ``tunnelNonce`` to get the preceding ``randNonce``
- ChaCha20 decrypt the received ``tunnelNonce`` using the hop's ``randKey`` and decrypted ``randNonce`` to get the preceding ``tunnelNonce``
- ChaCha20 decrypt the encrypted data using the decrypted ``tunnelNonce`` & the preceding hop's ``layerKey``
- Repeat the steps for nonce and layer decryption for each hop in the tunnel, back to the IBGW
- The AEAD frame decryption is only needed in the first round

.. raw:: html

  {% highlight lang='dataspec' %}

// For the first round, ChaCha20-Poly1305 decrypt each message's encrypted data frame + MAC
  // using the received tunnelNonce and receiveKey
  msg = encTunMsg || MAC
  tunnelNonce = received tunnelNonce
  encTunMsg = ChaCha20-Poly1305-Decrypt(msg, nonce = tunnelNonce, key = receiveKey)

  // Repeat for each hop in the tunnel back to the IBGW
  // For every round, ChaCha20 decrypt each hop's layer encryption on each message's encrypted data frame
  // Replace the received tunnelNonce w/ the prior round's decrypted tunnelNonce for each hop
  decMsg = ChaCha20(msg = encTunMsg, nonce = tunnelNonce, key = layerKey)
  randNonce = ChaCha20(msg = randNonce, nonce = tunnelNonce, key = randKey)
  tunnelNonce = ChaCha20(msg = tunnelNonce, nonce = randNonce, key = randKey)
{% endhighlight %}

Security Analysis for ChaCha20+ChaCha20-Poly1305 Tunnel Layer Encryption
------------------------------------------------------------------------

Switching from AES256/ECB+AES256/CBC to ChaCha20+ChaCha20-Poly1305 has a number of advantages, and new security considerations.

The biggest security considerations to account for, are that ChaCha20 and ChaCha20-Poly1305 nonces must be unique per-message,
for the life of the key being used.

Failing to use unique nonces with the same key on different messages breaks ChaCha20 and ChaCha20-Poly1305.

Using an appended ``randNonce`` allows the IBEP to decrypt the ``tunnelNonce`` for each hop's layer encryption,
recovering the previous nonce.

The ``randNonce`` alongside the ``tunnelNonce`` doesn't reveal any new information to tunnel hops,
since the ``randNonce`` is encrypted using the encrypted ``tunnelNonce``. This also allows the IBEP to recover
the previous ``randNonce`` in a similar way to ``tunnelNonce`` recovery.

The biggest security advantage is that there are no confirmation or oracle attacks against ChaCha20,
and using ChaCha20-Poly1305 between hops adds AEAD protection against ciphertext manipulation from
out-of-band MitM attackers.

There are practical oracle attacks against AES256/ECB + AES256/CBC, when the key is reused (as in tunnel layer encryption).

The oracle attacks against AES256/ECB won't work, because of the double-encryption used, and encryption is over a
single block (the tunnel IV).

The padding oracle attacks against AES256/CBC won't work, because no padding is used. If tunnel message length ever
changed to non-mod-16 lengths, AES256/CBC would still not be vulnerable due to rejected duplicate IVs.

Both attacks are also blocked by disallowing multiple oracle calls using the same IV, since duplicate IVs are rejected.

References
==========

.. [Tunnel-Implementation]
   https://geti2p.net/en/docs/tunnels/implementation
