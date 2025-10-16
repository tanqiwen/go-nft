package middlewares

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// CORS 跨域中间件
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// 简单的内存频率限制实现
var (
	ipRequests     = make(map[string][]time.Time)
	walletRequests = make(map[string][]time.Time)
	rateMutex      sync.RWMutex
)

// RateLimit 频率限制中间件
func RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 清理过期的请求记录
		cleanupRequests()

		// 获取客户端IP
		clientIP := c.ClientIP()

		// 检查IP频率限制（每分钟最多60次）
		if !checkAndIncrement(clientIP, ipRequests, 60, time.Minute) {
			c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "msg": "IP rate limit exceeded"})
			c.Abort()
			return
		}

		// 检查钱包地址频率限制（如果提供了）
		if address := c.Request.Header.Get("X-Wallet-Address"); address != "" {
			if !checkAndIncrement(address, walletRequests, 20, time.Minute) {
				c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "msg": "Wallet address rate limit exceeded"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// 检查并增加请求计数
func checkAndIncrement(key string, requestMap map[string][]time.Time, maxRequests int, duration time.Duration) bool {
	rateMutex.Lock()
	defer rateMutex.Unlock()

	now := time.Now()
	requests, exists := requestMap[key]

	if !exists {
		requestMap[key] = []time.Time{now}
		return true
	}

	// 过滤出指定时间范围内的请求
	validRequests := []time.Time{}
	for _, reqTime := range requests {
		if now.Sub(reqTime) < duration {
			validRequests = append(validRequests, reqTime)
		}
	}

	// 检查是否超过限制
	if len(validRequests) >= maxRequests {
		return false
	}

	// 增加新请求
	requestMap[key] = append(validRequests, now)
	return true
}

// 清理过期的请求记录
func cleanupRequests() {
	rateMutex.Lock()
	defer rateMutex.Unlock()

	now := time.Now()
	// 清理IP请求记录
	for key, requests := range ipRequests {
		validRequests := []time.Time{}
		for _, reqTime := range requests {
			if now.Sub(reqTime) < time.Minute {
				validRequests = append(validRequests, reqTime)
			}
		}
		if len(validRequests) == 0 {
			delete(ipRequests, key)
		} else {
			ipRequests[key] = validRequests
		}
	}

	// 清理钱包地址请求记录
	for key, requests := range walletRequests {
		validRequests := []time.Time{}
		for _, reqTime := range requests {
			if now.Sub(reqTime) < time.Minute {
				validRequests = append(validRequests, reqTime)
			}
		}
		if len(validRequests) == 0 {
			delete(walletRequests, key)
		} else {
			walletRequests[key] = validRequests
		}
	}
}