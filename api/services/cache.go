package services

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"live2d-api/config"
	"live2d-api/models"
)

// CacheEntry 缓存条目
type CacheEntry struct {
	Response *models.GenerateImageResponse
	Created  time.Time
	Accesses int
}

// RequestCache 请求缓存服务
type RequestCache struct {
	mu            sync.RWMutex
	cache         map[string]*CacheEntry
	maxEntries    int
	maxSizeMB     int
	currentSizeMB int
	ttl           time.Duration
	// 计数器在 Get（RLock 并发路径）上自增，必须用原子类型，
	// 不能在 RLock 保护下做普通 ++（确定性 data race）。
	hitCount  atomic.Int64
	missCount atomic.Int64
}

// NewRequestCache 创建新的缓存服务
func NewRequestCache(cfg config.CacheConfig) *RequestCache {
	return &RequestCache{
		cache:         make(map[string]*CacheEntry),
		maxEntries:    cfg.MaxEntries,
		maxSizeMB:     cfg.MaxSizeMB,
		currentSizeMB: 0,
		ttl:           time.Duration(cfg.TTLSeconds) * time.Second,
	}
}

// generateKey 生成缓存键
func (c *RequestCache) generateKey(prompt string, width, height, seed int, modelID string) string {
	key := fmt.Sprintf("%s|%d|%d|%d|%s", prompt, width, height, seed, modelID)
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash)[:16]
}

// Get 获取缓存
func (c *RequestCache) Get(prompt string, width, height, seed int, modelID string) (*models.GenerateImageResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.generateKey(prompt, width, height, seed, modelID)
	entry, exists := c.cache[key]

	if !exists {
		c.missCount.Add(1)
		return nil, false
	}

	// 检查是否过期
	if time.Since(entry.Created) > c.ttl {
		c.missCount.Add(1)
		return nil, false
	}

	// 注意：不要在这里自增 entry.Accesses——Get 只持有 RLock，
	// 多个读者并发写字段就是 data race。Accesses 当前无消费方，
	// 仅在 Set 创建条目时置 1。
	c.hitCount.Add(1)
	return entry.Response, true
}

// Set 设置缓存
func (c *RequestCache) Set(prompt string, width, height, seed int, modelID string, response *models.GenerateImageResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.generateKey(prompt, width, height, seed, modelID)

	// 计算条目大小（粗略估算）
	entrySizeMB := estimateSizeMB(response)

	// 覆盖同 key 时先回收旧条目容量，否则记账只增不减（容量漂移）
	if old, ok := c.cache[key]; ok {
		c.currentSizeMB -= estimateSizeMB(old.Response)
		delete(c.cache, key)
	}

	// 如果超出限制，先清理
	for c.currentSizeMB+entrySizeMB > c.maxSizeMB && len(c.cache) > 0 {
		c.evictOldest()
	}

	// 如果仍然超出限制，不缓存
	if c.currentSizeMB+entrySizeMB > c.maxSizeMB {
		return
	}

	// 检查条目数限制
	if len(c.cache) >= c.maxEntries && len(c.cache) > 0 {
		c.evictOldest()
	}

	c.cache[key] = &CacheEntry{
		Response: response,
		Created:  time.Now(),
		Accesses: 1,
	}
	c.currentSizeMB += entrySizeMB
}

// evictOldest 淘汰最老的缓存
func (c *RequestCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, entry := range c.cache {
		if entry.Created.Before(oldestTime) {
			oldestTime = entry.Created
			oldestKey = key
		}
	}

	if oldestKey != "" {
		entry := c.cache[oldestKey]
		c.currentSizeMB -= estimateSizeMB(entry.Response)
		delete(c.cache, oldestKey)
	}
}

// estimateSizeMB 估算条目占用（MB）。
//
// 缓存对象本身只是一个很小的 JSON，真正的成本是它引用的生成图片文件；因此以
// 磁盘上的实际文件大小为准（向上取整，最小 1MB），让 maxSizeMB 真正生效。
// 旧实现恒定返回 0，导致容量上限形同虚设（只有条目数上限在工作）。
func estimateSizeMB(response *models.GenerateImageResponse) int {
	if response == nil {
		return 0
	}
	if response.ImagePath != "" {
		if info, err := os.Stat(response.ImagePath); err == nil && info.Size() > 0 {
			mb := int((info.Size() + (1 << 20) - 1) >> 20)
			if mb < 1 {
				mb = 1
			}
			return mb
		}
	}
	// 文件不可达（路径为 URL 或已被删除）时给一个保守下限，而不是返回 0 ——
	// 否则容量上限又会被"算不出来"绕过。
	return 1
}

// Clear 清除所有缓存
func (c *RequestCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*CacheEntry)
	c.currentSizeMB = 0
	c.hitCount.Store(0)
	c.missCount.Store(0)
}

// Stats 获取缓存统计
func (c *RequestCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits := c.hitCount.Load()
	misses := c.missCount.Load()
	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"entries":         len(c.cache),
		"current_size_mb": c.currentSizeMB,
		"max_size_mb":     c.maxSizeMB,
		"hit_count":       hits,
		"miss_count":      misses,
		"hit_rate":        fmt.Sprintf("%.2f%%", hitRate),
	}
}

// PurgeExpired 清除过期缓存并同步回收容量记账
func (c *RequestCache) PurgeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.Sub(entry.Created) > c.ttl {
			c.currentSizeMB -= estimateSizeMB(entry.Response)
			delete(c.cache, key)
		}
	}
	if c.currentSizeMB < 0 {
		c.currentSizeMB = 0
	}
}

// StartCleanupDaemon 启动缓存清理守护进程
func (c *RequestCache) StartCleanupDaemon(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			c.PurgeExpired()
		}
	}()
}
