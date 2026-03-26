package capture

import (
	"context"
	"fmt"
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
	"sync"
)

type ServiceRule struct {
	DstIP    string
	DstPort  uint16
	JA4Entry *models.Ja4Entry
	SNIEntry *models.SNIEntry
}

type RuleCache struct {
	rules map[string]*ServiceRule
	mu    sync.RWMutex
	db    *clickhouse.ClickHouseStorage
}

func NewRuleCache(db *clickhouse.ClickHouseStorage) *RuleCache {
	return &RuleCache{
		rules: make(map[string]*ServiceRule),
		db:    db,
	}
}

func (c *RuleCache) LoadRules(ctx context.Context) error {
	rulesData, err := c.db.GetServiceRules(ctx)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, data := range rulesData {
		key := fmt.Sprintf("%s:%d", data.DstIP, data.DstPort)

		rule := &ServiceRule{
			DstIP:   data.DstIP,
			DstPort: data.DstPort,
		}

		if data.JA4EntryID != "" {
			rule.JA4Entry, _ = c.db.GetJA4ByID(ctx, data.JA4EntryID)
		}
		if data.SNIEntryID != "" {
			rule.SNIEntry, _ = c.db.GetSNIByID(ctx, data.SNIEntryID)
		}

		c.rules[key] = rule
	}

	return nil
}

func (c *RuleCache) Get(key string) *ServiceRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rules[key]
}

func (c *RuleCache) Add(dstIP string, dstPort uint16, ja4Entry *models.Ja4Entry, sniEntry *models.SNIEntry) {
	key := fmt.Sprintf("%s:%d", dstIP, dstPort)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[key] = &ServiceRule{
		DstIP:    dstIP,
		DstPort:  dstPort,
		JA4Entry: ja4Entry,
		SNIEntry: sniEntry,
	}
}
