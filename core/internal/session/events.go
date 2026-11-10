package session

import (
	"errors"
	"sync"
)

const DefaultEventQueue = 64

type Event struct {
	Name string `json:"event"`
	Data any    `json:"data"`
}

type Subscription struct {
	hub   *Hub
	id    uint64
	C     <-chan Event
	close sync.Once
}

type eventSubscriber struct {
	queue chan Event
	wants map[string]struct{}
}

type Hub struct {
	mu        sync.Mutex
	nextID    uint64
	queueSize int
	subs      map[uint64]*eventSubscriber
}

func NewHub(queueSize int) *Hub {
	if queueSize < 1 {
		queueSize = DefaultEventQueue
	}
	return &Hub{queueSize: queueSize, subs: make(map[uint64]*eventSubscriber)}
}

func (h *Hub) Subscribe(names []string) (*Subscription, error) {
	wants := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name != "status" && name != "traffic" && name != "log" {
			return nil, errors.New("unsupported event")
		}
		wants[name] = struct{}{}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	queue := make(chan Event, h.queueSize)
	h.subs[h.nextID] = &eventSubscriber{queue: queue, wants: wants}
	return &Subscription{hub: h, id: h.nextID, C: queue}, nil
}

func (s *Subscription) Close() {
	if s == nil || s.hub == nil {
		return
	}
	s.close.Do(func() { s.hub.remove(s.id) })
}

func (h *Hub) remove(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sub, ok := h.subs[id]; ok {
		delete(h.subs, id)
		close(sub.queue)
	}
}

func (h *Hub) Publish(name string, data any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, sub := range h.subs {
		if _, wanted := sub.wants[name]; !wanted {
			continue
		}
		select {
		case sub.queue <- Event{Name: name, Data: data}:
		default:
			delete(h.subs, id)
			close(sub.queue)
		}
	}
}

func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, sub := range h.subs {
		delete(h.subs, id)
		close(sub.queue)
	}
}
