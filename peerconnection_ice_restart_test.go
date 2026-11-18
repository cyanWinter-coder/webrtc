// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestDTLSRestartHandshake = errors.New("simulated DTLS handshake failure")

// restartPair performs a full non-trickled ICE restart offer/answer exchange,
// matching the signaling order used by TestICERestart.
func restartPair(t *testing.T, offerPC, answerPC *PeerConnection) {
	t.Helper()

	offer, err := offerPC.CreateOffer(&OfferOptions{ICERestart: true})
	require.NoError(t, err)

	offerGatheringComplete := GatheringCompletePromise(offerPC)
	require.NoError(t, offerPC.SetLocalDescription(offer))
	<-offerGatheringComplete
	require.NoError(t, answerPC.SetRemoteDescription(*offerPC.LocalDescription()))

	answer, err := answerPC.CreateAnswer(nil)
	require.NoError(t, err)

	answerGatheringComplete := GatheringCompletePromise(answerPC)
	require.NoError(t, answerPC.SetLocalDescription(answer))
	<-answerGatheringComplete
	require.NoError(t, offerPC.SetRemoteDescription(*answerPC.LocalDescription()))
}

func waitForDataChannelOpen(t *testing.T, dc *DataChannel) {
	t.Helper()

	if dc.ReadyState() == DataChannelStateOpen {
		return
	}

	opened := make(chan struct{})
	var once sync.Once
	dc.OnOpen(func() { once.Do(func() { close(opened) }) })

	select {
	case <-opened:
	case <-time.After(10 * time.Second):
		assert.FailNowf(t, "data channel did not open", dc.Label())
	}
}

func waitForPeerConnectionConnected(t *testing.T, pcs ...*PeerConnection) {
	t.Helper()

	done := untilConnectionState(PeerConnectionStateConnected, pcs...)

	// untilConnectionState only fires on a transition; if every peer is already
	// connected there is nothing to wait for.
	allConnected := true
	for _, pc := range pcs {
		if pc.ConnectionState() != PeerConnectionStateConnected {
			allConnected = false
		}
	}

	if allConnected {
		return
	}

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		assert.FailNow(t, "timed out waiting for PeerConnectionStateConnected after restart")
	}
}

// wireDataChannel registers the remote message handler for a channel
// identified by label. Handlers are registered before signaling so the initial
// data channel open is observed, matching the existing restart test pattern.
func wireDataChannel(receiver *PeerConnection, label string) chan string {
	got := make(chan string, 4)

	receiver.OnDataChannel(func(dc *DataChannel) {
		if dc.Label() != label {
			return
		}
		dc.OnMessage(func(msg DataChannelMessage) { got <- string(msg.Data) })
	})

	return got
}

func findDataChannel(t *testing.T, pc *PeerConnection, label string) *DataChannel {
	t.Helper()

	for _, dc := range pc.sctpTransport.dataChannels {
		if dc.Label() == label {
			return dc
		}
	}

	assert.FailNowf(t, "data channel not found after restart", label)

	return nil
}

func assertDataChannelRoundTrip(t *testing.T, pc *PeerConnection, label, message string, got chan string) {
	t.Helper()

	dc := findDataChannel(t, pc, label)
	require.Equal(t, DataChannelStateOpen, dc.ReadyState(), "data channel must stay open across the restart")
	require.NoError(t, dc.SendText(message))

	select {
	case received := <-got:
		assert.Equal(t, message, received)
	case <-time.After(5 * time.Second):
		assert.FailNow(t, "timed out waiting for data channel message after ICE restart")
	}
}

// Both peers may trigger ICE restarts back-to-back. Each restart exchange must
// resolve a unique DTLS client/server pair and keep the data channels usable.
func TestPeerConnection_ICERestart_SimultaneousRestarts(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	offerPC, answerPC, err := newPair()
	require.NoError(t, err)
	defer closePairNow(t, offerPC, answerPC)

	const label = "simultaneous"
	got := wireDataChannel(answerPC, label)

	dc, err := offerPC.CreateDataChannel(label, nil)
	require.NoError(t, err)

	connected := untilConnectionState(PeerConnectionStateConnected, offerPC, answerPC)
	require.NoError(t, signalPair(offerPC, answerPC))
	<-connected
	waitForDataChannelOpen(t, dc)

	// The two peers never hold identical roles once negotiated.
	initialOfferRole := offerPC.dtlsTransport.Role()
	initialAnswerRole := answerPC.dtlsTransport.Role()
	require.NotEqual(t, DTLSRoleUnknown, initialOfferRole)
	require.NotEqual(t, DTLSRoleUnknown, initialAnswerRole)
	assert.NotEqual(t, initialOfferRole, initialAnswerRole)

	// Restart in both directions, covering both signaling orders.
	restartPair(t, offerPC, answerPC)
	waitForPeerConnectionConnected(t, offerPC, answerPC)
	assert.GreaterOrEqual(t, offerPC.iceTransport.RestartCount(), uint32(1))
	assert.GreaterOrEqual(t, answerPC.iceTransport.RestartCount(), uint32(1))

	restartPair(t, answerPC, offerPC)
	waitForPeerConnectionConnected(t, offerPC, answerPC)
	assert.GreaterOrEqual(t, offerPC.iceTransport.RestartCount(), uint32(2))
	assert.GreaterOrEqual(t, answerPC.iceTransport.RestartCount(), uint32(2))

	// Roles remain a unique client/server pair and stay stable across restarts.
	assert.Equal(t, initialOfferRole, offerPC.dtlsTransport.Role())
	assert.Equal(t, initialAnswerRole, answerPC.dtlsTransport.Role())
	assert.NotEqual(t, offerPC.dtlsTransport.Role(), answerPC.dtlsTransport.Role())

	assertDataChannelRoundTrip(t, offerPC, label, "after-both-restarts", got)
}

// A restart initiated by only one side leaves the other peer connected, and its
// already-open data channels keep working with the same identifiers.
func TestPeerConnection_ICERestart_OneSidedRestart(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	offerPC, answerPC, err := newPair()
	require.NoError(t, err)
	defer closePairNow(t, offerPC, answerPC)

	const label = "one-sided"
	got := wireDataChannel(answerPC, label)

	dc, err := offerPC.CreateDataChannel(label, nil)
	require.NoError(t, err)

	connected := untilConnectionState(PeerConnectionStateConnected, offerPC, answerPC)
	require.NoError(t, signalPair(offerPC, answerPC))
	<-connected
	waitForDataChannelOpen(t, dc)

	idsBefore := offerPC.sctpTransport.dataChannelIdentifiers()
	require.NotEmpty(t, idsBefore)

	// The answerer performs the implicit ICE restart required when it receives
	// new remote credentials in the offer, even though it never creates an offer.
	restartPair(t, offerPC, answerPC)
	waitForPeerConnectionConnected(t, offerPC, answerPC)

	assert.GreaterOrEqual(t, offerPC.iceTransport.RestartCount(), uint32(1))
	assert.GreaterOrEqual(t, answerPC.iceTransport.RestartCount(), uint32(1))
	assert.Equal(t, PeerConnectionStateConnected, offerPC.ConnectionState())
	assert.Equal(t, PeerConnectionStateConnected, answerPC.ConnectionState())

	// The open data channels are preserved with identical identifiers.
	assert.Equal(t, idsBefore, offerPC.sctpTransport.dataChannelIdentifiers())
	assert.Equal(t, DataChannelStateOpen, dc.ReadyState())

	assertDataChannelRoundTrip(t, offerPC, label, "after-one-sided-restart", got)
}

// When the DTLS restart handshake fails, the transport/connection states must
// report the failure and the error is delivered through the data channel error
// events instead of being swallowed or reported as a successful recovery.
func TestPeerConnection_ICERestart_HandshakeFailure(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	offerPC, answerPC, err := newPair()
	require.NoError(t, err)
	defer closePairNow(t, offerPC, answerPC)

	const label = "failing"
	wireDataChannel(answerPC, label)

	dc, err := offerPC.CreateDataChannel(label, nil)
	require.NoError(t, err)

	connected := untilConnectionState(PeerConnectionStateConnected, offerPC, answerPC)
	require.NoError(t, signalPair(offerPC, answerPC))
	<-connected
	waitForDataChannelOpen(t, dc)

	handshakeErr := errTestDTLSRestartHandshake
	dataChannelErrors := make(chan error, 1)
	var openEvents atomic.Int32
	dc.OnError(func(err error) {
		select {
		case dataChannelErrors <- err:
		default:
		}
	})
	dc.OnOpen(func() { openEvents.Add(1) })

	dtlsFailed := make(chan struct{})
	var failOnce sync.Once
	offerPC.dtlsTransport.OnStateChange(func(state DTLSTransportState) {
		if state == DTLSTransportStateFailed {
			failOnce.Do(func() { close(dtlsFailed) })
		}
	})
	offerPC.dtlsTransport.restartHandshakeTestHook = func(DTLSRole) error {
		return handshakeErr
	}

	restartPair(t, offerPC, answerPC)

	select {
	case <-dtlsFailed:
	case <-time.After(5 * time.Second):
		assert.FailNow(t, "DTLS transport did not report DTLSTransportStateFailed")
	}

	assert.Equal(t, DTLSTransportStateFailed, offerPC.dtlsTransport.State())
	assert.Equal(t, PeerConnectionStateFailed, offerPC.ConnectionState())

	select {
	case receivedErr := <-dataChannelErrors:
		assert.ErrorIs(t, receivedErr, handshakeErr)
	case <-time.After(5 * time.Second):
		assert.FailNow(t, "data channel did not receive the restart error event")
	}

	// No fresh open event is emitted by the failed recovery, and the transport
	// is never reported as connected again.
	openCount := openEvents.Load()
	time.Sleep(time.Second)
	assert.Equal(t, openCount, openEvents.Load(), "no new data channel open event after the failed restart")
	assert.Equal(t, DTLSTransportStateFailed, offerPC.dtlsTransport.State())
}
