<!--
SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
SPDX-License-Identifier: MIT
-->

# ICE Restart and DTLS Role Renegotiation

This document describes how Pion WebRTC keeps the DTLS association and open data
channels alive while an ICE restart selects a new candidate pair, and how DTLS
role conflicts are detected and recovered.

## Background

An ICE restart (`CreateOffer` with `OfferOptions.ICERestart`, or the implicit
restart triggered by new remote ICE credentials in a remote offer) generates a
new ICE user fragment and password and re-gathers candidates. Per
[RFC 8842 section 5.3](https://www.rfc-editor.org/rfc/rfc8842.html#section-5.3),
the existing DTLS and SCTP associations are reused across the restart instead of
being torn down and re-established.

The DTLS role is derived from the offer/answer `setup` attribute
([RFC 5763](https://www.rfc-editor.org/rfc/rfc5763)):

- `setup:active` maps to the DTLS client.
- `setup:passive` maps to the DTLS server.
- The offerer sends `setup:actpass`; the answerer replies with either
  `setup:active` or `setup:passive`.

## Role Selection During a Restart

When a restart description is applied, the transport revalidates the role
pairing from the exchanged descriptions:

- The offerer becomes the DTLS server unless the answer selects
  `setup:active`, in which case the offerer is the client.
- The answerer keeps the concrete role already written into its local answer
  and the offerer takes the inverse role.

`DTLSTransport.Role()` reports the concrete role (`DTLSRoleClient` or
`DTLSRoleServer`) used by the current association; it is never
`DTLSRoleAuto` after negotiation.

## Conflict Detection and the Single Retry

A healthy offer/answer exchange always describes inverse roles. When both
peers nevertheless resolve to the same role (for example during a signaling
glare where both sides believe they are the DTLS client), the restart
negotiator detects the collision and:

1. Flips the local role once (client to server, or server to client) and
   retries the negotiation.
2. If the flipped pairing still collides, fails with `ErrDTLSRoleConflict`.

Exactly one retry is performed. There is no role-flipping loop and no unbounded
reconnection: the second conflict is reported to the caller. If a concrete role
cannot be derived from the descriptions, the restart fails with
`ErrDTLSRoleUndetermined` instead of guessing.

## Data Channel Preservation

Before the role is renegotiated, the SCTP transport snapshots the stream
identifiers of every registered data channel. Because the DTLS/SCTP association
is reused, already-open data channels keep their identifiers and continue
sending once the new ICE candidate pair is connected. If the snapshot changes
across the restart, a warning containing the connection identifier and the
before/after identifier sets is logged.

## Failure Handling and State Changes

Restart failures are never swallowed and a failed handshake is never reported
as success. On failure the transport:

- Moves `DTLSTransport` to `DTLSTransportStateFailed`, which drives the
  `PeerConnection` to `PeerConnectionStateFailed`.
- Logs the connection identifier together with the current and attempted
  roles, including ICE candidate gathering failures and handshake errors.
- Delivers the error to the SCTP transport and each data channel's `OnError`
  handler.
- Leaves the data channel ready state untouched, so a failed restart cannot
  emit a fresh open event or pretend the channel is usable.

`ICETransport.RestartCount()` exposes the number of completed ICE restarts for
correlating ICE generations with the DTLS role recovery. A one-sided restart
still causes the answerer to perform the implicit ICE restart required by the
new remote credentials; its data channels remain connected and usable.

## Initial Connection

The restart coordination only runs on renegotiation when the remote ICE
credentials change. The first offer/answer exchange continues to use the
existing `DTLSTransport.Start` path unchanged, so ordinary first-time
connection behavior and the public WebRTC API are unaffected.
