package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

// DefaultNATSConnectTimeout bounds the initial connection to the broker.
//
// It is a connect timeout only. A broker that is down at boot is not a boot
// failure — see NewNATSPublisher for why the outbox table, not the process's
// liveness, is what couples identity to the bus — so this bounds the wait for
// a broker that is slow to answer rather than one that is absent.
const DefaultNATSConnectTimeout = 5 * time.Second

// DefaultPublishTimeout bounds one publish's wait for the broker's ack.
//
// JetStream's PublishMsg is a request that blocks until the broker acks or the
// context dies, and the loop's context — the process's — has no deadline, so
// without a budget a single unanswered publish hangs the drain loop and holds
// its transaction open for the life of the process. The budget is applied
// inside Publish, so every caller is protected and not just the loop.
//
// Ten seconds is long enough that a slow-but-healthy broker never trips it (a
// healthy one acks in milliseconds) and short enough that a silent one costs
// the loop one bounded wait per event rather than the process's remaining
// lifetime. It is a package constant so a deployment can reason about the
// worst case: a full batch against a fully silent broker drains in at most
// DefaultBatchSize * DefaultPublishTimeout, loudly, with every row left
// claimable.
const DefaultPublishTimeout = 10 * time.Second

// NATSPublisher publishes envelopes to a NATS JetStream subject.
//
// # WHY JETSTREAM AND NOT CORE NATS
//
// The outbox contract sets `published_at` from the broker's ack: a row marked
// published that the broker never saw is an event announced and lost, which is
// the failure the table exists to prevent. Core NATS' Publish returns when the
// message is on the wire, not when the broker has stored it, so marking on its
// return would mark rows published that were never delivered. JetStream's
// PublishMsg is a request that blocks until the broker acks, so a nil return
// from Publish IS the ack the loop marks the row from — "ack, then mark" is
// the call, not a convention layered around it.
//
// # THE PUBLISH IS BOUNDED BY A BUDGET, AND AN UNANSWERED PUBLISH IS A FAILURE
//
// "Until the broker acks" is not the same as "forever". PublishMsg is a select
// on the reply inbox and the context's Done channel, so a broker that neither
// acks nor errors — a half-configured stream, a network black hole, a
// JetStream layer that is up but has no matching stream and no core
// subscriber — blocks the call for as long as the context allows. The loop
// runs on the process's context, which has no deadline, so an unbounded
// publish is a publish that can hang the drain loop (and hold its transaction
// open) for the life of the process. Publish therefore applies
// DefaultPublishTimeout to every call: a publish that is not acknowledged
// within the budget returns an error, which is what the loop records in
// last_error and what leaves the row claimable for the next pass. The budget
// is the difference between a slow broker and a wedged one.
//
// # THE SUBJECT IS THE EVENT TYPE
//
// core's event-outbox.md: "No mapping table, no prefix rewriting." A row with
// type `identity.session.revoked` is published on the subject
// `identity.session.revoked` and nothing else. The subject is read off the
// envelope, so a new event type needs no change in this file.
//
// # THE STREAM IS THE STACK'S, NOT THIS PACKAGE'S
//
// A JetStream publish to a subject no stream matches fails, and that failure
// is correct: it leaves the row claimable with attempts incremented, and the
// event leaves the table only once a stream exists that covers its subject.
// Creating one here would mean this service choosing a stream name, a retention
// policy and a replication factor for the fleet's bus — deployment decisions
// that belong to the NATS stack. kit's compose runs the broker with `-js` and
// defines no streams, so the fleet-level fact this packet imposes is: **the
// stack must define a stream whose subject filter covers what identity
// publishes (e.g. `identity.>`), or every publish fails and no event ever
// leaves the table.** The failure is loud — attempts climbs, last_error names
// the refusal — which is the direction a misconfiguration should fail in.
type NATSPublisher struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

// NewNATSPublisher connects to the broker at url and returns a publisher over
// its JetStream context.
//
// RetryOnFailedConnect is the whole of the boot-time resilience, and it is a
// deliberate choice rather than an omission: a broker that is down when the
// process starts is NOT a startup failure. The outbox table is the durable
// store — rows accumulate while the broker is away and drain when it returns,
// which is the entire point of publishing from a table rather than from the
// request path. The connection reconnects on its own; publishes made while it
// is down fail, the loop marks those rows failed, and the next pass retries
// them. Refusing to boot without a bus would couple the auth surface to the
// bus's availability, turning an event delay into an authentication outage.
//
// nats.go reconnects a dropped connection by default — but only within its
// reconnect budget, which defaults to 60 attempts at a 2-second wait: about
// two minutes (60 × 2s = 120s). When the budget is exhausted the client
// closes the connection, and `nats: connection closed` is what every later
// publish sees. It is terminal. That budget contradicts the paragraph above,
// which is the reason this is a defect rather than a tuning question: a
// durable outbox exists so the broker can be away for as long as it likes; a
// two-minute budget means it can be away for two minutes. MaxReconnects(-1)
// is nats.go's "never give up", and it is what that paragraph requires — a
// publisher whose durable store is the table must not have a deadline on the
// broker's return.
//
// The connection state is said once. The WARN per failed publish is right —
// it names the row and the error — and what was missing is the one line that
// says the connection closed and will be retried, so an operator reading the
// log can tell "the broker is away" from "this pod is broken". A
// DisconnectErrHandler/ClosedHandler pair is where that belongs; a line per
// retry is how a real defect gets buried, so there is no ReconnectErrHandler
// and no per-publish log here.
//
// What this DOES refuse is a url that does not parse: a typo is a deployment
// that believes it has a bus and does not, and that belongs at boot where an
// operator reads it, not at the first event where nobody does.
func NewNATSPublisher(url string, logger *slog.Logger) (*NATSPublisher, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.Timeout(DefaultNATSConnectTimeout),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("nats connection disconnected; will retry", "error", err)
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			if err := c.LastError(); err != nil {
				logger.Warn("nats connection closed", "error", err)
			} else {
				logger.Info("nats connection closed")
			}
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("outbox: connecting to the NATS broker: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("outbox: opening the JetStream context: %w", err)
	}

	return &NATSPublisher{nc: nc, js: js}, nil
}

// Publish puts one envelope on the subject named by its type.
//
// It returns nil only after the broker has acked, and an error otherwise. The
// wait is bounded by DefaultPublishTimeout: a publish that is not acknowledged
// within the budget is a failure, not a wait — the error is what the loop
// records in last_error and what leaves the row claimable for the next pass,
// and the row is never marked published on this path. A canceled context (a
// shutdown) aborts an in-flight publish the same way, because the budget is
// derived from the caller's context.
func (p *NATSPublisher) Publish(ctx context.Context, e Envelope) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("outbox: marshaling the envelope: %w", err)
	}

	publishCtx, cancel := context.WithTimeout(ctx, DefaultPublishTimeout)
	defer cancel()

	if _, err := p.js.PublishMsg(&nats.Msg{Subject: e.Type, Data: payload}, nats.Context(publishCtx)); err != nil {
		return fmt.Errorf("outbox: publishing %s: %w", e.Type, err)
	}
	return nil
}

// Close closes the broker connection.
//
// It is safe to call after the loop has stopped, and safe to call concurrently
// with a publish in flight — the publish fails, which is the outcome a shutdown
// wants. It is not an error to close twice.
func (p *NATSPublisher) Close() {
	p.nc.Close()
}
