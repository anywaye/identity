package outbox

import (
	"context"
	"encoding/json"
	"fmt"
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

// NATSPublisher publishes envelopes to a NATS JetStream subject.
//
// # WHY JETSTREAM AND NOT CORE NATS
//
// The outbox contract sets `published_at` from the broker's ack: a row marked
// published that the broker never saw is an event announced and lost, which is
// the failure the table exists to prevent. Core NATS' Publish returns when the
// message is on the wire, not when the broker has stored it, so marking on its
// return would mark rows published that were never delivered. JetStream's
// PublishMsg is a request that blocks until the broker acks (or the context
// dies), so a nil return from Publish IS the ack the loop marks the row from —
// "ack, then mark" is the call, not a convention layered around it.
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
// What this DOES refuse is a url that does not parse: a typo is a deployment
// that believes it has a bus and does not, and that belongs at boot where an
// operator reads it, not at the first event where nobody does.
func NewNATSPublisher(url string) (*NATSPublisher, error) {
	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.Timeout(DefaultNATSConnectTimeout),
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
// It returns nil only after the broker has acked, and an error otherwise —
// including when the context dies mid-publish, which is how a shutdown aborts
// an in-flight publish instead of letting it hold the loop's transaction open.
// The error is what the loop records in last_error and what leaves the row
// claimable for the next pass; the row is never marked published on this path.
func (p *NATSPublisher) Publish(ctx context.Context, e Envelope) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("outbox: marshalling the envelope: %w", err)
	}

	if _, err := p.js.PublishMsg(&nats.Msg{Subject: e.Type, Data: payload}, nats.Context(ctx)); err != nil {
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
