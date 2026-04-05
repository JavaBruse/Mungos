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

	logger.Info("Loading %d rules from database", len(rulesData))

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
		logger.Info("Loaded rule: key=%s, ja4=%v, sni=%v", key, rule.JA4Entry != nil, rule.SNIEntry != nil)
	}

	logger.Info("Total rules loaded: %d", len(c.rules))
	return nil
}

func (c *RuleCache) Get(key string) *ServiceRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rules[key]
}

func (c *RuleCache) Add(ctx context.Context, dstIP string, dstPort uint16, ja4Entry *models.Ja4Entry, sniEntry *models.SNIEntry) {
	key := fmt.Sprintf("%s:%d", dstIP, dstPort)
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
		logger.Info("Rule created: key=%s, ja4=%v, sni=%v", key, ja4Entry != nil, sniEntry != nil)
		c.db.UpdatePacketsInsight(ctx, dstIP, dstPort, ja4Entry, sniEntry)
	} else {
		if ja4Entry != nil && existing.JA4Entry == nil {
			existing.JA4Entry = ja4Entry
			logger.Info("Rule updated: key=%s, JA4 added", key)
			c.db.UpdatePacketsInsight(ctx, dstIP, dstPort, ja4Entry, sniEntry)
		}
		if sniEntry != nil && existing.SNIEntry == nil {
			existing.SNIEntry = sniEntry
			logger.Info("Rule updated: key=%s, SNI added", key)
			c.db.UpdatePacketsInsight(ctx, dstIP, dstPort, ja4Entry, sniEntry)
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
			logger.Info("ApplyRule: (прямые пакеты) looking for key=%s", key)
			if rule.JA4Entry != nil {
				fillPacketFromEntry(packet, rule.JA4Entry)
			}
			if rule.SNIEntry != nil {
				packet.SNI = rule.SNIEntry.SNI
				if packet.SNIService == "" {
					packet.SNIService = rule.SNIEntry.Service
				}
			}
			return true
		}
	}

	// Проверяем по src (обратные пакеты)
	if packet.SrcIPType == "public" {
		key := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
		if rule := c.Get(key); rule != nil {
			logger.Info("ApplyRule: (обратные пакеты) looking for key=%s", key)
			if rule.JA4Entry != nil {
				fillPacketFromEntry(packet, rule.JA4Entry)
			}
			if rule.SNIEntry != nil {
				packet.SNI = rule.SNIEntry.SNI
				if packet.SNIService == "" {
					packet.SNIService = rule.SNIEntry.Service
				}
			}
			return true
		}
	}

	return false
}

func (c *RuleCache) UpdateFromPacket(packet *models.Packet, db *clickhouse.ClickHouseStorage) {
	if packet == nil || c == nil {
		return
	}

	if packet.JA4Raw == "" && packet.SNI == "" {
		return
	}

	var remoteIP string
	var remotePort uint16
	if packet.DstIPType == "public" {
		remoteIP = packet.DstIP
		remotePort = packet.DstPort
	} else if packet.SrcIPType == "public" {
		remoteIP = packet.SrcIP
		remotePort = packet.SrcPort
	}

	if remoteIP == "" {
		return
	}

	key := fmt.Sprintf("%s:%d", remoteIP, remotePort)
	existing := c.Get(key)
	if existing != nil && existing.JA4Entry != nil && existing.SNIEntry != nil {
		return
	}

	var ja4Entry *models.Ja4Entry
	var sniEntry *models.SNIEntry

	if packet.JA4Raw != "" {
		ja4Entry, _ = db.LookupJA4(context.Background(), packet.JA4Raw)
	}
	if packet.SNI != "" {
		sniEntry, _ = db.LookupSNIBySNI(context.Background(), packet.SNI)
	}

	if ja4Entry != nil || sniEntry != nil {
		c.Add(context.Background(), remoteIP, remotePort, ja4Entry, sniEntry)
	}
}
