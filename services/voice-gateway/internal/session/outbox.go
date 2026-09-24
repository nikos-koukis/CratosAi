package session

import (
	"context"
	"errors"
	"sync"
	"time"

	voicev1 "jarvis.internal/gen/go/jarvis/voice/v1"
)

var errOutboxFull = errors.New("client is not reading fast enough")

// outItem is a message waiting to be written to the client.
type outItem struct {
	msg *voicev1.ServerMessage
	// For audio: the assistant item it belongs to and its size.
	itemID     string
	audioBytes int
	enqueued   time.Time
}

// outbox is the bounded queue between the provider and the client writer.
// Unlike a channel it can drop queued audio at once, which is what barge-in
// needs, and it tracks how much of each assistant item reached the client.
type outbox struct {
	mu        sync.Mutex
	items     []outItem
	capacity  int
	notify    chan struct{}
	delivered map[string]int
}

func newOutbox(capacity int) *outbox {
	return &outbox{capacity: capacity, notify: make(chan struct{}, 1), delivered: map[string]int{}}
}

func (o *outbox) push(item outItem) error {
	o.mu.Lock()
	if len(o.items) >= o.capacity {
		o.mu.Unlock()
		return errOutboxFull
	}
	o.items = append(o.items, item)
	o.mu.Unlock()
	select {
	case o.notify <- struct{}{}:
	default:
	}
	return nil
}

// pop blocks until an item is available or ctx ends.
func (o *outbox) pop(ctx context.Context) (outItem, error) {
	for {
		o.mu.Lock()
		if len(o.items) > 0 {
			item := o.items[0]
			o.items[0] = outItem{}
			o.items = o.items[1:]
			o.mu.Unlock()
			return item, nil
		}
		o.mu.Unlock()
		select {
		case <-o.notify:
		case <-ctx.Done():
			return outItem{}, ctx.Err()
		}
	}
}

// markDelivered records that an audio item reached the client.
func (o *outbox) markDelivered(item outItem) {
	if item.audioBytes == 0 {
		return
	}
	o.mu.Lock()
	o.delivered[item.itemID] += item.audioBytes
	o.mu.Unlock()
}

// dropAudio removes every queued audio chunk. It returns how many bytes of
// `itemID` were dropped and how many had already been delivered.
func (o *outbox) dropAudio(itemID string) (dropped, delivered int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	kept := o.items[:0]
	for _, item := range o.items {
		if item.audioBytes > 0 {
			if item.itemID == itemID {
				dropped += item.audioBytes
			}
			continue
		}
		kept = append(kept, item)
	}
	clear(o.items[len(kept):])
	o.items = kept
	return dropped, o.delivered[itemID]
}

func (o *outbox) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.items)
}
