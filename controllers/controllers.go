// 首先导入log包
package controllers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/go-nft/models"
)

// 然后为所有错误处理添加日志记录

// Test 测试接口
func Test(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok"})
}

// UploadImage64 上传Base64图片
func UploadImage64(c *gin.Context) {
	var req struct {
		HSeed       string `json:"hseed" binding:"required"`
		Base64Image string `json:"base64Image" binding:"required"`
		Address     string `json:"address" binding:"required"`
		CollectID   string `json:"collectId" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[UploadImage64] Failed to bind request parameters: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid request parameters"})
		return
	}

	// 移除Base64前缀
	imageData := req.Base64Image
	if strings.HasPrefix(imageData, "data:image/") {
		parts := strings.Split(imageData, ",")
		if len(parts) > 1 {
			imageData = parts[1]
		}
	}

	// 解码Base64
	decodedData, err := base64.StdEncoding.DecodeString(imageData)
	if err != nil {
		log.Printf("[UploadImage64] Base64 decoding failed: %v, hseed: %s", err, req.HSeed)
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Base64 decoding failed"})
		return
	}

	// 验证是否为有效图片
	_, format, err := image.Decode(bytes.NewReader(decodedData))
	if err != nil {
		log.Printf("[UploadImage64] Image format validation failed: %v, hseed: %s", err, req.HSeed)
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid image data"})
		return
	}

	// 保存到数据库
	img := &models.CollectionImage{
		HSeed:       req.HSeed,
		CollectID:   req.CollectID,
		ImageBase64: req.Base64Image,
		Address:     req.Address,
	}

	if err := models.CreateOrUpdateImage(img); err != nil {
		log.Printf("[UploadImage64] Database operation failed: %v, hseed: %s, address: %s", err, req.HSeed, req.Address)
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "Database operation failed"})
		return
	}

	// 更新种子状态
	seedUsed := &models.SeedUsed{
		Address: req.Address,
		HSeed:   req.HSeed,
		State:   2, // 已处理图片
	}
	if err := models.MarkSeedAsUsed(seedUsed); err != nil {
		log.Printf("[UploadImage64] Failed to update seed status: %v, hseed: %s", err, req.HSeed)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "Base64 image uploaded successfully and updated to collection information",
		"data": gin.H{
			"id":         img.ID,
			"hseed":      img.HSeed,
			"collect_id": img.CollectID,
			"address":    img.Address,
			"image_type": fmt.Sprintf("image/%s", format),
		},
	})
}

func UpdateImage(c *gin.Context) {
	var req struct {
		HSeed       string `json:"hseed" binding:"required"`
		Base64Image string `json:"base64Image" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[UpdateImage] Failed to bind request parameters: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid request parameters"})
		return
	}

	// 检查图片是否存在
	existingImg, err := models.GetImageByHSeed(req.HSeed)
	if err != nil {
		log.Printf("[UpdateImage] Failed to get image: %v, hseed: %s", err, req.HSeed)
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "Image not found"})
		return
	}

	// 移除Base64前缀
	imageData := req.Base64Image
	if strings.HasPrefix(imageData, "data:image/") {
		parts := strings.Split(imageData, ",")
		if len(parts) > 1 {
			imageData = parts[1]
		}
	}

	// 解码Base64
	decodedData, err := base64.StdEncoding.DecodeString(imageData)
	if err != nil {
		log.Printf("[UpdateImage] Base64 decoding failed: %v, hseed: %s", err, req.HSeed)
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Base64 decoding failed"})
		return
	}

	// 验证是否为有效图片
	_, format, err := image.Decode(bytes.NewReader(decodedData))
	if err != nil {
		log.Printf("[UpdateImage] Image format validation failed: %v, hseed: %s", err, req.HSeed)
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid image data"})
		return
	}

	// 更新图片
	existingImg.ImageBase64 = req.Base64Image
	if err := models.CreateOrUpdateImage(existingImg); err != nil {
		log.Printf("[UpdateImage] Database operation failed: %v, hseed: %s", err, req.HSeed)
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "Database operation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "图片更新成功",
		"data": gin.H{
			"hseed":         req.HSeed,
			"image_type":    fmt.Sprintf("image/%s", format),
			"affected_rows": 1,
		},
	})
}

// GetStaticImage 获取静态图片
func GetStaticImage(c *gin.Context) {
	collectId := c.Param("collectId")
	hseed := c.Query("hseed")

	if collectId == "" || hseed == "" {
		log.Printf("[GetStaticImage] Missing required parameters: collectId=%s, hseed=%s", collectId, hseed)
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid request parameters"})
		return
	}

	// 从数据库获取图片
	img, err := models.GetImageByCollectIDAndHSeed(collectId, hseed)
	if err != nil {
		log.Printf("[GetStaticImage] Failed to get image: %v, collectId: %s, hseed: %s", err, collectId, hseed)
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "Image not found"})
		return
	}

	// 移除Base64前缀
	imageData := img.ImageBase64
	if strings.HasPrefix(imageData, "data:image/") {
		parts := strings.Split(imageData, ",")
		if len(parts) > 1 {
			imageData = parts[1]
		}
	}

	// 解码Base64
	decodedData, err := base64.StdEncoding.DecodeString(imageData)
	if err != nil {
		log.Printf("[GetStaticImage] Image decoding failed: %v, collectId: %s, hseed: %s", err, collectId, hseed)
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "Image decoding failed"})
		return
	}

	// 将图片保存到本地临时目录（可选）
	staticDir := filepath.Join(".", "static", collectId)
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		log.Printf("[GetStaticImage] Failed to create directory: %v, dir: %s", err, staticDir)
	}

	imagePath := filepath.Join(staticDir, fmt.Sprintf("%s.png", hseed))
	if err := os.WriteFile(imagePath, decodedData, 0644); err != nil {
		log.Printf("[GetStaticImage] 保存图片失败: %v, path: %s", err, imagePath)
	}

	// Set response header and return image data
	c.Header("Content-Type", "image/png")
	c.Data(http.StatusOK, "image/png", decodedData)
}

// RequestSeed 申请新种子
func RequestSeed(c *gin.Context) {
	address := c.Query("address")
	if address == "" {
		log.Printf("[RequestSeed] Missing address parameter")
		c.JSON(http.StatusBadRequest, gin.H{"hSeed": "", "success": false, "message": "Address cannot be empty"})
		return
	}

	// 生成随机种子
	hseed, err := generateRandomSeed()
	if err != nil {
		log.Printf("[RequestSeed] Failed to generate random seed: %v, address: %s", err, address)
		c.JSON(http.StatusInternalServerError, gin.H{"hSeed": "", "success": false, "message": "Failed to generate seed"})
		return
	}

	// 检查种子是否已存在
	for i := 0; i < 5; i++ { // 最多重试5次
		exists, err := models.IsSeedExists(hseed)
		if err != nil {
			log.Printf("[RequestSeed] Failed to check if seed exists: %v, hseed: %s", err, hseed)
		}
		if !exists {
			break
		}
		hseed, err = generateRandomSeed()
		if err != nil {
			log.Printf("[RequestSeed] Failed to regenerate random seed: %v, address: %s", err, address)
			c.JSON(http.StatusInternalServerError, gin.H{"hSeed": "", "success": false, "message": "Failed to generate seed"})
			return
		}
	}

	// 保存种子订单
	order := &models.SeedOrder{
		Address: address,
		HSeed:   hseed,
	}
	if err := models.CreateSeedOrder(order); err != nil {
		log.Printf("[RequestSeed] Failed to save seed order: %v, address: %s, hseed: %s", err, address, hseed)
		c.JSON(http.StatusInternalServerError, gin.H{"hSeed": "", "success": false, "message": "Failed to save seed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"hSeed":   hseed,
		"success": true,
		"message": "OK",
	})
}

// UseSeed 标记种子为已使用
func UseSeed(c *gin.Context) {
	var req struct {
		HSeed   string `json:"hSeed" binding:"required"`
		Address string `json:"address" binding:"required"`
		TxHash  string `json:"txhash" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[UseSeed] Failed to bind request parameters: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request parameters"})
		return
	}

	seedUsed := &models.SeedUsed{
		Address: req.Address,
		HSeed:   req.HSeed,
		TxHash:  req.TxHash,
		State:   1, // 已使用
	}

	if err := models.MarkSeedAsUsed(seedUsed); err != nil {
		log.Printf("[UseSeed] Failed to mark seed: %v, hseed: %s, address: %s", err, req.HSeed, req.Address)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to mark seed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Seed marked as used",
	})
}

// UseSeedPreTx 标记种子为已使用（预交易）
func UseSeedPreTx(c *gin.Context) {
	var req struct {
		HSeed   string `json:"hSeed" binding:"required"`
		Address string `json:"address" binding:"required"`
		TxHash  string `json:"txhash" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[UseSeedPreTx] Failed to bind request parameters: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request parameters"})
		return
	}

	seedUsed := &models.SeedUsed{
		Address: req.Address,
		HSeed:   req.HSeed,
		TxHash:  req.TxHash,
		State:   1, // 已使用
	}

	if err := models.MarkSeedAsUsedPreTx(seedUsed); err != nil {
		log.Printf("[UseSeedPreTx] Failed to mark seed: %v, hseed: %s, address: %s", err, req.HSeed, req.Address)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to mark seed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Seed marked as used",
	})
}

// GetSeeds 获取已使用种子列表
func GetSeeds(c *gin.Context) {
	startIndex, _ := strconv.Atoi(c.DefaultQuery("startIndex", "0"))
	count, _ := strconv.Atoi(c.DefaultQuery("count", "10"))

	// 限制最大数量
	if count > 100 {
		count = 100
	}

	seeds, totalCount, err := models.GetUsedSeeds(startIndex, count)
	if err != nil {
		log.Printf("[GetSeeds] Failed to get seed list: %v, startIndex: %d, count: %d", err, startIndex, count)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to get seed list"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"hSeeds":     seeds,
		"count":      len(seeds),
		"startIndex": startIndex,
		"totalCount": totalCount,
	})
}

// GenerateChallenge 生成挑战码
func GenerateChallenge(c *gin.Context) {
	var req struct {
		Address string `json:"address" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid request parameters"})
		return
	}

	// 获取客户端IP
	clientIP := c.ClientIP()

	// 检查频率限制
	allowed, err := models.CheckRateLimit(clientIP, req.Address)
	if err != nil {
		log.Printf("[GenerateChallenge] Failed to check rate limit: %v, ip: %s, address: %s", err, clientIP, req.Address)
		c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "msg": "Rate limit exceeded"})
		return
	}
	if !allowed {
		log.Printf("[GenerateChallenge] Rate limit triggered: ip: %s, address: %s", clientIP, req.Address)
		c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "msg": "Rate limit exceeded"})
		return
	}

	// 生成挑战码
	challengeCode, err := generateRandomChallenge()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "Failed to generate challenge code"})
		return
	}

	// 保存挑战码
	challenge := &models.ChallengeCode{
		ChallengeCode: challengeCode,
		WalletAddress: req.Address,
		IPAddress:     clientIP,
		ExpiresAt:     time.Now().Add(10 * time.Minute), // 10 minutes expiration
	}

	if err := models.CreateChallengeCode(challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "Failed to save challenge code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge": challengeCode,
	})
}

// GenerateSignature 生成签名（带挑战码验证）
func GenerateSignature(c *gin.Context) {
	var req struct {
		HSeed     string `json:"hSeed" binding:"required"`
		Address   string `json:"address" binding:"required"`
		ChainId   int    `json:"chainId" binding:"required"`
		Challenge string `json:"challenge" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
		return
	}

	// 验证挑战码
	valid, err := models.VerifyChallengeCode(req.Challenge, req.Address)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "无效的挑战码"})
		return
	}
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "无效的挑战码"})
		return
	}

	// 生成签名
	signature := generateDummySignature(req.HSeed, req.Address, req.ChainId)

	c.JSON(http.StatusOK, gin.H{
		"hSeed":     req.HSeed,
		"signature": signature,
	})
}

// GenerateSignatureNoChallenge 生成签名（无挑战码验证）
func GenerateSignatureNoChallenge(c *gin.Context) {
	var req struct {
		HSeed   string `json:"hSeed" binding:"required"`
		Address string `json:"address" binding:"required"`
		ChainId int    `json:"chainId" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
		return
	}

	// 生成签名
	signature := generateDummySignature(req.HSeed, req.Address, req.ChainId)

	c.JSON(http.StatusOK, gin.H{
		"hSeed":     req.HSeed,
		"signature": signature,
	})
}

// IsWhiteAddress 检查地址是否在白名单中且未被使用
func IsWhiteAddress(c *gin.Context) {
	var req struct {
		Address string `json:"address" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
		return
	}

	isWhitelisted, err := models.IsAddressInWhitelist(req.Address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "查询失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"address":       req.Address,
		"isWhitelisted": isWhitelisted,
	})
}

// IsWhiteAddressXDCheck 检查地址是否在白名单中（不检查使用状态）
func IsWhiteAddressXDCheck(c *gin.Context) {
	var req struct {
		Address string `json:"address" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
		return
	}

	isWhitelisted, err := models.IsAddressInWhitelistXDCheck(req.Address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "查询失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"address":       req.Address,
		"isWhitelisted": isWhitelisted,
	})
}

// 生成随机种子
func generateRandomSeed() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("Failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// 生成随机挑战码
func generateRandomChallenge() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("Failed to generate random bytes: %w", err)
	}
	return "0x" + hex.EncodeToString(bytes), nil
}

// 生成ECDSA签名，与Solidity中的验证逻辑匹配
func generateDummySignature(hseed, address string, chainId int) string {
	// 这里只是模拟，实际应该使用ECDSA等算法进行签名
	data := fmt.Sprintf("%s:%s:%d:%d", hseed, address, chainId, time.Now().Unix())
	bytes := []byte(data)
	return "0x" + hex.EncodeToString(bytes)
}
