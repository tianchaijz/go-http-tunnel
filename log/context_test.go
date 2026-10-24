package log

import (
	"reflect"
	"sync"
	"testing"
)

type contextRecorder struct {
	mu     sync.Mutex
	events [][]interface{}
}

func (r *contextRecorder) Log(keyvals ...interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, keyvals)
	return nil
}

func TestContextSiblingsIndependent(t *testing.T) {
	for _, tt := range []struct {
		name string
		with func(*Context, ...interface{}) *Context
	}{
		{"suffix", (*Context).With},
		{"prefix", (*Context).WithPrefix},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &contextRecorder{}
			parent := tt.with(tt.with(tt.with(NewContext(r), "a", 1), "b", 2), "c", 3)
			left := tt.with(parent, "branch", "left")
			right := tt.with(parent, "branch", "right")
			left.Log()
			right.Log()
			parent.Log()
			want := [][]interface{}{
				{"a", 1, "b", 2, "c", 3, "branch", "left"},
				{"a", 1, "b", 2, "c", 3, "branch", "right"},
				{"a", 1, "b", 2, "c", 3},
			}
			if !reflect.DeepEqual(r.events, want) {
				t.Fatalf("events = %v, want %v", r.events, want)
			}
		})
	}
}

func TestContextLogPreservesEarlierEvents(t *testing.T) {
	r := &contextRecorder{}
	c := NewContext(r).WithPrefix("a", 1).WithPrefix("b", 2).WithPrefix("c", 3)
	c.Log("event", "first")
	c.Log("event", "second")
	want := [][]interface{}{
		{"a", 1, "b", 2, "c", 3, "event", "first"},
		{"a", 1, "b", 2, "c", 3, "event", "second"},
	}
	if !reflect.DeepEqual(r.events, want) {
		t.Fatalf("events = %v, want %v", r.events, want)
	}
}

func TestContextConcurrentDerivationAndLogging(t *testing.T) {
	r := &contextRecorder{}
	parent := NewContext(r).
		WithPrefix("a", 1).WithPrefix("b", 2).WithPrefix("c", 3).
		With("d", 4).With("e", 5).With("f", 6)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			for j := 0; j < 16; j++ {
				id := i*16 + j
				parent.With("worker", id).WithPrefix("request", id).Log("event", id)
			}
		}(i)
	}
	close(start)
	workers.Wait()
	if len(r.events) != 256 {
		t.Fatalf("logged %d events, want 256", len(r.events))
	}
	seen := make(map[int]bool)
	for _, event := range r.events {
		if len(event) != 18 {
			t.Fatalf("invalid event: %v", event)
		}
		id, ok := event[9].(int)
		if !ok || id < 0 || id >= 256 || seen[id] {
			t.Fatalf("invalid or duplicate event: %v", event)
		}
		seen[id] = true
		want := []interface{}{"a", 1, "b", 2, "c", 3, "request", id, "event", id,
			"d", 4, "e", 5, "f", 6, "worker", id}
		if !reflect.DeepEqual(event, want) {
			t.Fatalf("event = %v, want %v", event, want)
		}
	}
}
