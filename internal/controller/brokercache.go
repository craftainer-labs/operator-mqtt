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
// connection is no longer alive. It is dropped, and its connection closed, when
// the broker is gone (Forget) or has not been used for a while. A nil
// *BrokerCache caches nothing.
type BrokerCache struct {
	mu      sync.Mutex
	idle    time.Duration
	now     func() time.Time
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	version string
	broker  Broker
	used    time.Time
}

// NewBrokerCache returns a cache that drops an entry idle for longer than idle.
func NewBrokerCache(idle time.Duration) *BrokerCache {
	return &BrokerCache{idle: idle, now: time.Now, entries: map[string]*cacheEntry{}}
}

// Get returns the connection cached for key if it was made for version and is
// alive, else connects through build, replaces the entry and closes the old
// connection. A failed build caches nothing. build runs with the lock held: a
// broker that does not answer holds up the other brokers' reconciles for the
// connect timeout, which is the price of a cache without a second lock.
func (c *BrokerCache) Get(ctx context.Context, key, version string, build func(context.Context) (Broker, error)) (Broker, error) {
	if c == nil {
		return build(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.entries {
		if now.Sub(e.used) > c.idle {
			c.drop(k)
		}
	}
	if e, ok := c.entries[key]; ok && e.version == version && e.broker.Alive() {
		e.used = now
		return e.broker, nil
	}
	c.drop(key)
	b, err := build(ctx)
	if err != nil {
		return nil, err
	}
	c.entries[key] = &cacheEntry{version: version, broker: b, used: now}
	return b, nil
}

// Forget drops the entry of a broker that no longer exists.
func (c *BrokerCache) Forget(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drop(key)
}

// Len is the number of cached brokers.
func (c *BrokerCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// drop removes an entry and closes its connection. The caller holds mu.
func (c *BrokerCache) drop(key string) {
	e, ok := c.entries[key]
	if !ok {
		return
	}
	delete(c.entries, key)
	e.broker.Close()
}
