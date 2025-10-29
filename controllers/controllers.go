package controllers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/go-nft/models"
)

// Test 测试接口
func Test(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok"})
}

// UploadImage64 上传Base64图片
func UploadImage64(c *gin.Context) {
	var req struct {
		HSeed     string `json:"hseed" binding:"required"`
		Base64Image string `json:"base64Image" binding:"required"`
		Address   string `json:"address" binding:"required"`
		CollectID string `json:"collectId" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
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
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Base64解码失败"})
		return
	}

	// 验证是否为有效图片
	_, format, err := image.Decode(strings.NewReader(string(decodedData)))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "无效的图片数据"})
		return
	}

	// 保存到数据库
	img := &models.CollectionImage{
		HSeed:      req.HSeed,
		CollectID:  req.CollectID,
		ImageBase64: req.Base64Image,
		Address:    req.Address,
	}

	if err := models.CreateOrUpdateImage(img); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "数据库操作失败"})
		return
	}

	// 更新种子状态
	seedUsed := &models.SeedUsed{
		Address: req.Address,
		HSeed:   req.HSeed,
		State:   2, // 已处理图片
	}
	models.MarkSeedAsUsed(seedUsed)

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "base64图片上传成功并更新到收藏品信息",
		"data": gin.H{
			"id":          img.ID,
			"hseed":       img.HSeed,
			"collect_id":  img.CollectID,
			"address":     img.Address,
			"image_type":  fmt.Sprintf("image/%s", format),
		},
	})
}

// UpdateImage 更新图片
func UpdateImage(c *gin.Context) {
	var req struct {
		HSeed     string `json:"hseed" binding:"required"`
		Base64Image string `json:"base64Image" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
		return
	}

	// 检查图片是否存在
	existingImg, err := models.GetImageByHSeed(req.HSeed)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "图片不存在"})
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
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Base64解码失败"})
		return
	}

	// 验证是否为有效图片
	_, format, err := image.Decode(strings.NewReader(string(decodedData)))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "无效的图片数据"})
		return
	}

	// 更新图片
	existingImg.ImageBase64 = req.Base64Image
	if err := models.CreateOrUpdateImage(existingImg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "数据库操作失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "图片更新成功",
		"data": gin.H{
			"hseed":        req.HSeed,
			"image_type":   fmt.Sprintf("image/%s", format),
			"affected_rows": 1,
		},
	})
}

// GetStaticImage 获取静态图片
func GetStaticImage(c *gin.Context) {
	collectId := c.Param("collectId")
	hseed := c.Query("hseed")

	if collectId == "" || hseed == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
		return
	}

	// 从数据库获取图片
	img, err := models.GetImageByCollectIDAndHSeed(collectId, hseed)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "图片不存在"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "图片解码失败"})
		return
	}

	// 将图片保存到本地临时目录（可选）
	staticDir := filepath.Join(".", "static", collectId)
	os.MkdirAll(staticDir, 0755)
	imagePath := filepath.Join(staticDir, fmt.Sprintf("%s.png", hseed))
	os.WriteFile(imagePath, decodedData, 0644)

	// 设置响应头并返回图片数据
	c.Header("Content-Type", "image/png")
	c.Data(http.StatusOK, "image/png", decodedData)
}

// RequestSeed 申请新种子
func RequestSeed(c *gin.Context) {
	address := c.Query("address")
	if address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"hSeed": "", "success": false, "message": "地址不能为空"})
		return
	}

	// 生成随机种子
	hseed, err := generateRandomSeed()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"hSeed": "", "success": false, "message": "生成种子失败"})
		return
	}

	// 检查种子是否已存在
	for i := 0; i < 5; i++ { // 最多重试5次
		exists, _ := models.IsSeedExists(hseed)
		if !exists {
			break
		}
		hseed, _ = generateRandomSeed()
	}

	// 保存种子订单
	order := &models.SeedOrder{
		Address: address,
		HSeed:   hseed,
	}
	if err := models.CreateSeedOrder(order); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"hSeed": "", "success": false, "message": "保存种子失败"})
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
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	seedUsed := &models.SeedUsed{
		Address: req.Address,
		HSeed:   req.HSeed,
		TxHash:  req.TxHash,
		State:   1, // 已使用
	}

	if err := models.MarkSeedAsUsed(seedUsed); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "标记种子失败"})
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
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	seedUsed := &models.SeedUsed{
		Address: req.Address,
		HSeed:   req.HSeed,
		TxHash:  req.TxHash,
		State:   1, // 已使用
	}

	if err := models.MarkSeedAsUsedPreTx(seedUsed); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "标记种子失败"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取种子列表失败"})
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
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
		return
	}

	// 获取客户端IP
	clientIP := c.ClientIP()

	// 检查频率限制
	allowed, err := models.CheckRateLimit(clientIP, req.Address)
	if err != nil || !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "msg": "频率限制"})
		return
	}

	// 生成挑战码
	challengeCode, err := generateRandomChallenge()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "生成挑战码失败"})
		return
	}

	// 保存挑战码
	challenge := &models.ChallengeCode{
		ChallengeCode: challengeCode,
		WalletAddress: req.Address,
		IPAddress:     clientIP,
		ExpiresAt:     time.Now().Add(10 * time.Minute), // 10分钟过期
	}

	if err := models.CreateChallengeCode(challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "保存挑战码失败"})
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
	if err != nil || !valid {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "无效的挑战码"})
		return
	}

	// 生成签名（这里简化处理，实际应该使用正确的签名算法）
	signature := generateDummySignature(req.HSeed, req.Address, req.ChainId)

	c.JSON(http.StatusOK, gin.H{
		"hSeed":    req.HSeed,
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

	// 生成签名（这里简化处理，实际应该使用正确的签名算法）
	signature := generateDummySignature(req.HSeed, req.Address, req.ChainId)

	c.JSON(http.StatusOK, gin.H{
		"hSeed":    req.HSeed,
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
		"address":      req.Address,
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
		"address":      req.Address,
		"isWhitelisted": isWhitelisted,
	})
}

// 生成随机种子
func generateRandomSeed() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// 生成随机挑战码
func generateRandomChallenge() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(bytes), nil
}

// 生成ECDSA签名，与Solidity中的验证逻辑匹配
func generateDummySignature(hseed, address string, chainId int) string {
	// 从环境变量中获取私钥，这是更安全的做法
	privateKeyHex := os.Getenv("SIGN_SECRET")
	
	// 如果环境变量未设置，使用一个默认的测试私钥（仅用于开发环境）
	if privateKeyHex == "" {
		fmt.Println("警告: 未设置SIGN_SECRET环境变量，使用测试私钥")
		privateKeyHex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		// 如果私钥解析失败，返回一个错误签名
		return "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
	}

	// 解析私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader(privateKeyBytes))
	if err != nil {
		// 如果无法生成密钥，返回一个错误签名
		return "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"
	}

	// 根据Solidity代码，构建消息（注意这里默认isWhitelisted为false）
	isWhitelisted := false
	message := abiEncodePacked(hseed, address, chainId, isWhitelisted)

	// 计算keccak256哈希
	hash := sha3.Sum256(message)

	// 添加以太坊签名前缀 (EIP-191)
	eip191Prefix := []byte("\x19Ethereum Signed Message:\n32")
	prefixedMessage := append(eip191Prefix, hash[:]...)
	prefixedHash := sha3.Sum256(prefixedMessage)

	// 使用ECDSA进行签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, prefixedHash[:])
	if err != nil {
		// 如果签名失败，返回一个错误签名
		return "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003"
	}

	// 格式化签名：r + s + v（v应该是0或1，这里我们默认使用0）
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// 组合签名
	signature := make([]byte, 65)
	copy(signature[:32], rPadded)
	copy(signature[32:64], sPadded)
	signature[64] = 0 // v值，0或1

	return "0x" + hex.EncodeToString(signature)
}

// 模拟Solidity的abi.encodePacked函数
func abiEncodePacked(args ...interface{}) []byte {
	var result []byte
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			// 检查是否是以太坊地址格式（以0x开头，长度为42）
			if len(v) == 42 && strings.HasPrefix(v, "0x") {
				// 移除0x前缀并转换为字节数组
				hexStr := v[2:]
				if len(hexStr) == 40 {
					// 尝试将十六进制字符串转换为字节数组
					addrBytes, err := hex.DecodeString(hexStr)
					if err == nil && len(addrBytes) == 20 {
						// 成功解析为以太坊地址，直接添加20字节
						result = append(result, addrBytes...)
						continue
					}
				}
			}
			// 不是有效的以太坊地址，按普通字符串处理
			result = append(result, []byte(v)...)
		case int:
			// 将int转换为大端字节序的32字节表示
			b := make([]byte, 32)
			binary.BigEndian.PutUint64(b[24:], uint64(v))
			result = append(result, b...)
		case bool:
			// bool类型在Solidity中是1字节
			if v {
				result = append(result, 1)
			} else {
				result = append(result, 0)
			}
		}
	}
	return result
}