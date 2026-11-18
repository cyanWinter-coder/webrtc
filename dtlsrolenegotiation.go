// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"fmt"

	"github.com/pion/sdp/v3"
)

// resolveDTLSRoleForRestart determines the concrete DTLS role (never
// DTLSRoleAuto) an endpoint must use during an ICE restart.
//
// The offerer advertises setup:actpass and becomes the DTLS server unless its
// answer explicitly requests setup:active (RFC 5763). The answerer mirrors the
// offerer's setup attribute and takes the inverse role. The previously
// negotiated DTLS association is reused, so the resolved roles stay stable
// across restarts (RFC 8842 Section 5.3).
func resolveDTLSRoleForRestart(localDesc, remoteDesc *sdp.SessionDescription, isOfferer bool) (DTLSRole, error) {
	var role DTLSRole
	switch {
	case isOfferer:
		// The answerer's setup attribute describes the inverse pairing: a
		// passive (server) answerer makes the offerer the client, while an
		// active answerer or an actpass answer leaves the offerer as server.
		role = DTLSRoleServer
		if dtlsRoleFromSDP(remoteDesc) == DTLSRoleServer {
			role = DTLSRoleClient
		}
	case localDesc != nil:
		role = dtlsRoleFromSDP(localDesc)
		if role == DTLSRoleAuto {
			return DTLSRoleUnknown, ErrDTLSRoleUndetermined
		}
	default:
		return DTLSRoleUnknown, ErrDTLSRoleUndetermined
	}

	if role != DTLSRoleClient && role != DTLSRoleServer {
		return DTLSRoleUnknown, fmt.Errorf("%w: resolved %s", ErrDTLSRoleUndetermined, role)
	}

	return role, nil
}

// inferRemoteDTLSRoleForRestart derives the role the remote peer resolved to.
// For the offerer the answer carries an explicit setup attribute; for the
// answerer the local answer already describes the inverse pairing.
func inferRemoteDTLSRoleForRestart(localDesc, remoteDesc *sdp.SessionDescription, isOfferer bool) (DTLSRole, error) {
	if isOfferer {
		role := dtlsRoleFromSDP(remoteDesc)
		if role == DTLSRoleAuto {
			return DTLSRoleUnknown, ErrDTLSRoleUndetermined
		}

		return role, nil
	}

	if localDesc == nil {
		return DTLSRoleUnknown, ErrDTLSRoleUndetermined
	}

	role := dtlsRoleFromSDP(localDesc)
	if role == DTLSRoleAuto {
		return DTLSRoleUnknown, ErrDTLSRoleUndetermined
	}

	return flipDTLSRole(role), nil
}

// flipDTLSRole swaps the DTLS client and server roles. Unknown or auto roles
// are rejected because a conflict retry requires a concrete alternative role.
func flipDTLSRole(role DTLSRole) DTLSRole {
	switch role {
	case DTLSRoleClient:
		return DTLSRoleServer
	case DTLSRoleServer:
		return DTLSRoleClient
	default:
		return DTLSRoleUnknown
	}
}

// dtlsRoleRestartNegotiation carries the offer/answer context needed to
// renegotiate the DTLS role while an ICE restart is in progress.
type dtlsRoleRestartNegotiation struct {
	connectionID string
	localDesc    *sdp.SessionDescription
	remoteDesc   *sdp.SessionDescription
	isOfferer    bool
	// simulatedRemoteRole overrides the remote role inferred from SDP. It is
	// only used by tests to exercise the role-conflict retry path, since
	// well-formed offer/answer descriptions always describe inverse roles.
	simulatedRemoteRole DTLSRole
}

// dtlsRoleRestartNegotiator resolves the local DTLS role for one restart
// attempt and, when both peers selected the same role, retries exactly once
// with the inverted role. A second conflict is reported instead of looping.
type dtlsRoleRestartNegotiator struct {
	negotiation dtlsRoleRestartNegotiation
	retried     bool
	role        DTLSRole
	remoteRole  DTLSRole
}

func newDTLSRoleRestartNegotiator(negotiation dtlsRoleRestartNegotiation) *dtlsRoleRestartNegotiator {
	return &dtlsRoleRestartNegotiator{negotiation: negotiation}
}

// Next returns the role to attempt and whether the single retry was consumed.
// The first call resolves the pairing and, on a collision, returns the flipped
// role. A subsequent call re-checks the original collision and fails with
// ErrDTLSRoleConflict instead of looping.
func (n *dtlsRoleRestartNegotiator) Next() (DTLSRole, bool, error) {
	if n.role == DTLSRoleUnknown {
		role, err := resolveDTLSRoleForRestart(
			n.negotiation.localDesc,
			n.negotiation.remoteDesc,
			n.negotiation.isOfferer,
		)
		if err != nil {
			return DTLSRoleUnknown, false, err
		}

		remoteRole, err := inferRemoteDTLSRoleForRestart(
			n.negotiation.localDesc,
			n.negotiation.remoteDesc,
			n.negotiation.isOfferer,
		)
		if err != nil {
			return DTLSRoleUnknown, false, err
		}
		if n.negotiation.simulatedRemoteRole != DTLSRoleUnknown {
			remoteRole = n.negotiation.simulatedRemoteRole
		}

		n.role = role
		n.remoteRole = remoteRole
	}

	role, remoteRole := n.role, n.remoteRole

	// On the second (and any later) call the single retry has already been
	// consumed: another collision fails instead of looping forever.
	if n.retried {
		if role == remoteRole {
			return DTLSRoleUnknown, true, fmt.Errorf(
				"%w: connection %s local %s remote %s",
				ErrDTLSRoleConflict,
				n.negotiation.connectionID,
				role,
				remoteRole,
			)
		}

		return role, true, nil
	}

	if role != remoteRole {
		return role, false, nil
	}

	n.retried = true

	flipped := flipDTLSRole(role)
	if flipped == DTLSRoleUnknown {
		return DTLSRoleUnknown, true, ErrDTLSRoleUndetermined
	}

	return flipped, true, nil
}
