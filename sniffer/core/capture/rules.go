package capture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sniffer/core/logger"
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
)

var (
	globalRuleCache *RuleCache
	globalOnce      sync.Once
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

func InitRuleCache(db *clickhouse.ClickHouseStorage) {
	globalOnce.Do(func() {
		globalRuleCache = NewRuleCache(db)
		if db != nil && db.Enabled() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			globalRuleCache.LoadRules(ctx)
		}
	})
}

func GetRuleCache() *RuleCache {
	return globalRuleCache
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

		if data.JA4Raw != "" {
			rule.JA4Entry, _ = c.db.LookupJA4(ctx, data.JA4Raw)
		}
		if data.SNIRaw != "" {
			rule.SNIEntry, _ = c.db.LookupSNIBySNI(ctx, data.SNIRaw)
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
	logger.Info("Adding rule to cache: key=%s, ja4=%v, sni=%v", key, ja4Entry != nil, sniEntry != nil)
	c.mu.Lock()
	defer c.mu.Unlock()

	existing := c.rules[key]
	if existing == nil {
		c.rules[key] = &ServiceRule{
			DstIP:    dstIP,
			DstPort:  dstPort,
			JA4Entry: ja4Entry,
			SNIEntry: sniEntry,
		}
	} else {
		if ja4Entry != nil {
			existing.JA4Entry = ja4Entry
		}
		if sniEntry != nil {
			existing.SNIEntry = sniEntry
		}
	}
}

func (c *RuleCache) ApplyRule(packet *models.Packet) bool {
	if c == nil {
		return false
	}

	// Проверяем по dst (прямые пакеты)
	if packet.DstIPType == "public" {
		key := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)
		if rule := c.Get(key); rule != nil {
			if rule.JA4Entry != nil {
				fillPacketFromEntry(packet, rule.JA4Entry)
			}
			if rule.SNIEntry != nil {
				packet.SNIService = rule.SNIEntry.Service
				if packet.SNI == "" {
					packet.SNI = rule.SNIEntry.SNI
				}
			}
			return true
		}
	}

	// Проверяем по src (обратные пакеты)
	if packet.SrcIPType == "public" && (packet.JA4Raw == "" || packet.SNI == "") {
		key := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
		if rule := c.Get(key); rule != nil {
			if rule.JA4Entry != nil {
				fillPacketFromEntry(packet, rule.JA4Entry)
			}
			if rule.SNIEntry != nil {
				packet.SNIService = rule.SNIEntry.Service
				if packet.SNI == "" {
					packet.SNI = rule.SNIEntry.SNI
				}
			}
			return true
		}
	}

	return false
}
