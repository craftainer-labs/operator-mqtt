package controller

import (
	"context"
	"sync"
	"time"
)

// BrokerCache keeps one logged-in connection per broker between reconciles, so
// the operator logs in once instead of for every reconcile. An entry is valid
// for one version, the stamp: the broker object (its UID and generation) and
// everything its connection is made from (credentials, CA, proxy), so it is
// replaced as soon as any of them changes, and it is replaced when the
// connection is no longer alive.
//
// Get hands out a lease: the connection and a release function. A replaced or
// forgotten entry is only marked stale; its connection is closed when the last
// lease on it is released, so a reconcile never loses the connection it uses.
// An entry nobody holds a lease on and nobody used for the idle time is closed
// by the next Get or by the sweep that Start runs. A nil *BrokerCache caches
// nothing: its leases close the connection on release.
type BrokerCache struct {
	mu      sync.Mutex
	idle    time.Duration
	now     func() time.Time
	tick    func(time.Duration) (<-chan time.Time, func())
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	version string
	broker  Broker
	used    time.Time
	leases  int
	stale   bool
}

// NewBrokerCache returns a cache that closes an unused entry idle for longer than idle.
func NewBrokerCache(idle time.Duration) *BrokerCache {
	return &BrokerCache{idle: idle, now: time.Now, tick: newTicker, entries: map[string]*cacheEntry{}}
}

func newTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Get returns a lease on the connection cached for key if it was made for
// version and is alive, else connects through build, replaces the entry and
// retires the old connection. The caller calls the release function once it is
// done with the connection, and not before. A failed build caches nothing.
// build runs with the lock held: a broker that does not answer holds up the
// other brokers' reconciles for the connect timeout, which is the price of a
// cache without a second lock.
func (c *BrokerCache) Get(ctx context.Context, key, version string, build func(context.Context) (Broker, error)) (Broker, func(), error) {
	if c == nil {
		b, err := build(ctx)
		if err != nil {
			return nil, nil, err
		}
		return b, b.Close, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweep(now)
	if e, ok := c.entries[key]; ok && e.version == version && e.broker.Alive() {
		return c.lease(e, now)
	}
	c.retire(key)
	b, err := build(ctx)
	if err != nil {
		return nil, nil, err
	}
	e := &cacheEntry{version: version, broker: b, used: now}
	c.entries[key] = e
	return c.lease(e, now)
}

// lease counts a new holder of e. The caller holds mu.
func (c *BrokerCache) lease(e *cacheEntry, now time.Time) (Broker, func(), error) {
	e.leases++
	e.used = now
	released := false
	return e.broker, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if released {
			return
		}
		released = true
		e.leases--
		e.used = c.now()
		if e.stale && e.leases == 0 {
			e.broker.Close()
		}
	}, nil
}

// Forget retires the entry of a broker that no longer exists.
func (c *BrokerCache) Forget(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retire(key)
}

// Len is the number of cached brokers.
func (c *BrokerCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// retire removes an entry from the cache. Its connection is closed now when
// nobody holds a lease on it, else by the release of the last lease. The caller
// holds mu.
func (c *BrokerCache) retire(key string) {
	e, ok := c.entries[key]
	if !ok {
		return
	}
	delete(c.entries, key)
	e.stale = true
	if e.leases == 0 {
		e.broker.Close()
	}
}

// sweep retires the entries nobody holds a lease on and nobody used for longer
// than the idle time. The caller holds mu.
func (c *BrokerCache) sweep(now time.Time) {
	for k, e := range c.entries {
		if e.leases == 0 && now.Sub(e.used) > c.idle {
			c.retire(k)
		}
	}
}

// Start implements manager.Runnable: it sweeps the idle entries every
// half idle period, so the connection to a broker nobody reconciles any more
// is closed without waiting for a Get. It returns when ctx is cancelled, and
// closes what is left once nobody holds it.
func (c *BrokerCache) Start(ctx context.Context) error {
	ticks, stop := c.tick(max(c.idle/2, time.Second))
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
			c.mu.Lock()
			c.sweep(c.now())
			c.mu.Unlock()
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable: every replica
// closes its own idle connections.
func (c *BrokerCache) NeedLeaderElection() bool { return false }
