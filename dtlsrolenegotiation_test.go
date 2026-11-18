// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"testing"

	"github.com/pion/sdp/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sdpWithSetup(role sdp.ConnectionRole) *sdp.SessionDescription {
	return &sdp.SessionDescription{
		MediaDescriptions: []*sdp.MediaDescription{
			{
				Attributes: []sdp.Attribute{{Key: "setup", Value: role.String()}},
			},
		},
	}
}

func TestResolveDTLSRoleForRestart(t *testing.T) {
	t.Run("offerer becomes server for passive answer", func(t *testing.T) {
		role, err := resolveDTLSRoleForRestart(
			sdpWithSetup(sdp.ConnectionRoleActpass),
			sdpWithSetup(sdp.ConnectionRolePassive),
			true,
		)
		require.NoError(t, err)
		assert.Equal(t, DTLSRoleClient, role)
	})

	t.Run("offerer becomes server for active answer", func(t *testing.T) {
		role, err := resolveDTLSRoleForRestart(
			sdpWithSetup(sdp.ConnectionRoleActpass),
			sdpWithSetup(sdp.ConnectionRoleActive),
			true,
		)
		require.NoError(t, err)
		assert.Equal(t, DTLSRoleServer, role)
	})

	t.Run("answerer keeps role from its own answer", func(t *testing.T) {
		role, err := resolveDTLSRoleForRestart(
			sdpWithSetup(sdp.ConnectionRoleActive),
			sdpWithSetup(sdp.ConnectionRoleActpass),
			false,
		)
		require.NoError(t, err)
		assert.Equal(t, DTLSRoleClient, role)
	})

	t.Run("answerer without concrete role fails", func(t *testing.T) {
		_, err := resolveDTLSRoleForRestart(nil, sdpWithSetup(sdp.ConnectionRoleActpass), false)
		assert.ErrorIs(t, err, ErrDTLSRoleUndetermined)
	})

	t.Run("nil descriptions never produce auto role", func(t *testing.T) {
		_, err := resolveDTLSRoleForRestart(nil, nil, false)
		assert.ErrorIs(t, err, ErrDTLSRoleUndetermined)

		role, err := resolveDTLSRoleForRestart(nil, nil, true)
		require.NoError(t, err)
		assert.NotEqual(t, DTLSRoleAuto, role)
	})
}

func TestInferRemoteDTLSRoleForRestart(t *testing.T) {
	role, err := inferRemoteDTLSRoleForRestart(
		sdpWithSetup(sdp.ConnectionRolePassive),
		sdpWithSetup(sdp.ConnectionRoleActpass),
		false,
	)
	require.NoError(t, err)
	assert.Equal(t, DTLSRoleClient, role)

	role, err = inferRemoteDTLSRoleForRestart(
		sdpWithSetup(sdp.ConnectionRoleActpass),
		sdpWithSetup(sdp.ConnectionRoleActive),
		true,
	)
	require.NoError(t, err)
	assert.Equal(t, DTLSRoleClient, role)

	_, err = inferRemoteDTLSRoleForRestart(nil, sdpWithSetup(sdp.ConnectionRoleActpass), true)
	assert.ErrorIs(t, err, ErrDTLSRoleUndetermined)
}

func TestFlipDTLSRole(t *testing.T) {
	assert.Equal(t, DTLSRoleServer, flipDTLSRole(DTLSRoleClient))
	assert.Equal(t, DTLSRoleClient, flipDTLSRole(DTLSRoleServer))
	assert.Equal(t, DTLSRoleUnknown, flipDTLSRole(DTLSRoleAuto))
	assert.Equal(t, DTLSRoleUnknown, flipDTLSRole(DTLSRoleUnknown))
}

func TestDTLSRoleRestartNegotiator_NoConflict(t *testing.T) {
	// Offerer (local actpass) with passive answer: local client, remote server.
	negotiator := newDTLSRoleRestartNegotiator(dtlsRoleRestartNegotiation{
		connectionID: "pc-1",
		localDesc:    sdpWithSetup(sdp.ConnectionRoleActpass),
		remoteDesc:   sdpWithSetup(sdp.ConnectionRolePassive),
		isOfferer:    true,
	})

	role, retried, err := negotiator.Next()
	require.NoError(t, err)
	assert.False(t, retried)
	assert.Equal(t, DTLSRoleClient, role)
}

func TestDTLSRoleRestartNegotiator_ConflictRetriesOnce(t *testing.T) {
	// A glare makes both peers resolve to the same role. Well-formed SDP
	// always carries inverse roles, so the remote collision is injected via
	// the test seam; the local offerer would normally become the client.
	negotiator := newDTLSRoleRestartNegotiator(dtlsRoleRestartNegotiation{
		connectionID:        "pc-1",
		localDesc:           sdpWithSetup(sdp.ConnectionRoleActpass),
		remoteDesc:          sdpWithSetup(sdp.ConnectionRolePassive),
		isOfferer:           true,
		simulatedRemoteRole: DTLSRoleClient,
	})

	role, retried, err := negotiator.Next()
	require.NoError(t, err)
	assert.True(t, retried, "the first conflict must consume the single retry")
	assert.Equal(t, DTLSRoleServer, role, "the flipped role must invert the collision")

	// A subsequent conflict on the same negotiation is not retried again.
	_, _, err = negotiator.Next()
	assert.ErrorIs(t, err, ErrDTLSRoleConflict)
}

func TestDTLSRoleRestartNegotiator_UndeterminedRole(t *testing.T) {
	negotiator := newDTLSRoleRestartNegotiator(dtlsRoleRestartNegotiation{
		connectionID: "pc-1",
		localDesc:    nil,
		remoteDesc:   sdpWithSetup(sdp.ConnectionRoleActpass),
		isOfferer:    false,
	})

	_, retried, err := negotiator.Next()
	assert.ErrorIs(t, err, ErrDTLSRoleUndetermined)
	assert.False(t, retried)
}
