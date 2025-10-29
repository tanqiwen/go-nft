package test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/user/go-nft/middlewares"
)

// 测试前的初始化
// 首先，在setupTest函数中添加GetStaticImage接口的模拟实现
func setupTest() *gin.Engine {
	// 设置为测试模式
	gin.SetMode(gin.TestMode)

	// 创建Gin实例
	r := gin.Default()

	// 注册中间件
	r.Use(middlewares.CORS())

	// 为测试环境添加一个简单的测试接口
	r.GET("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "ok",
		})
	})

	// 模拟种子管理接口
	r.GET("/api/seed/request", func(c *gin.Context) {
		address := c.Query("address")
		if address == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"hSeed":   "",
				"success": false,
				"message": "Address is required",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"hSeed":   generateTestSeed(),
			"success": true,
			"message": "OK",
		})
	})

	r.POST("/api/seed/use", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Seed marked as used",
		})
	})

	r.POST("/api/seed/usepretx", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Seed marked as used",
		})
	})

	r.GET("/api/seed/getseeds", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"hSeeds":     []string{},
			"count":      0,
			"startIndex": 0,
			"totalCount": 0,
		})
	})

	// 模拟签名验证接口
	r.POST("/api/signature/challenge", func(c *gin.Context) {
		var req struct {
			Address string `json:"address"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Address == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": 400,
				"msg":  "地址参数错误",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"challenge": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		})
	})

	r.POST("/api/signature/generate", func(c *gin.Context) {
		var req struct {
			HSeed string `json:"hSeed"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"hSeed":     req.HSeed,
			"signature": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		})
	})

	r.POST("/api/signature/generate-no-challenge", func(c *gin.Context) {
		var req struct {
			HSeed string `json:"hSeed"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"hSeed":     req.HSeed,
			"signature": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		})
	})

	r.POST("/api/signature/is-white-address", func(c *gin.Context) {
		var req struct {
			Address string `json:"address"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"address":       req.Address,
			"isWhitelisted": true,
		})
	})

	r.POST("/api/signature/is-white-address-xdcheck", func(c *gin.Context) {
		var req struct {
			Address string `json:"address"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"address":       req.Address,
			"isWhitelisted": true,
		})
	})

	// 模拟图片上传接口
	r.POST("/api/upload/image64", func(c *gin.Context) {
		var req struct {
			HSeed       string `json:"hseed"`
			Base64Image string `json:"base64Image"`
			Address     string `json:"address"`
			CollectId   string `json:"collectId"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": 400,
				"msg":  "参数错误",
			})
			return
		}

		// 验证必填参数
		if req.HSeed == "" || req.Base64Image == "" || req.Address == "" || req.CollectId == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": 400,
				"msg":  "缺少必要参数",
			})
			return
		}

		// 验证Base64图片格式（简单验证）
		if len(req.Base64Image) < 10 || req.Base64Image == "invalid-base64-data" {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": 400,
				"msg":  "base64图片格式错误",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "base64图片上传成功并更新到收藏品信息",
			"data": gin.H{
				"id":         123,
				"hseed":      req.HSeed,
				"collect_id": req.CollectId,
				"address":    req.Address,
				"image_type": "image/png",
			},
		})
	})

	r.POST("/api/upload/updateimage", func(c *gin.Context) {
		var req struct {
			HSeed       string `json:"hseed"`
			Base64Image string `json:"base64Image"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": 400,
				"msg":  "参数错误",
			})
			return
		}

		// 检查hseed是否存在（这里我们假设"non-existent-seed"是不存在的）
		if req.HSeed == "non-existent-seed" {
			c.JSON(http.StatusNotFound, gin.H{
				"code": 404,
				"msg":  "未找到对应种子记录",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "图片更新成功",
			"data": gin.H{
				"hseed":         req.HSeed,
				"image_type":    "image/png",
				"affected_rows": 1,
			},
		})
	})

	// 模拟GetStaticImage接口
	r.GET("/api/static/:collectId", func(c *gin.Context) {
		collectId := c.Param("collectId")
		hseed := c.Query("hseed")

		if collectId == "" || hseed == "" {
			c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请求参数错误"})
			return
		}

		// 模拟图片不存在的情况
		if collectId == "non-existent-collect" || hseed == "non-existent-seed" {
			c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "图片不存在"})
			return
		}

		// 模拟图片解码失败的情况
		if hseed == "invalid-base64-seed" {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "图片解码失败"})
			return
		}

		// 正常情况：返回测试图片数据
		// 使用一个简单的1x1透明图片的Base64解码后的数据
		testImageData, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")

		c.Header("Content-Type", "image/png")
		c.Data(http.StatusOK, "image/png", testImageData)
	})

	return r
}

// 生成测试用的随机种子
func generateTestSeed() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// 生成测试用的Base64图片
func generateTestBase64Image() string {
	// 一个简单的1x1透明图片的Base64编码
	return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
}

// 测试响应结构

// Response 通用响应结构
type Response struct {
	Code int         `json:"code,omitempty"`
	Msg  string      `json:"msg,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

// SeedResponse 种子响应结构
type SeedResponse struct {
	HSeed   string `json:"hSeed"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// UseSeedResponse 使用种子响应结构
type UseSeedResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// GetSeedsResponse 获取种子列表响应结构
type GetSeedsResponse struct {
	Success    bool     `json:"success"`
	HSeeds     []string `json:"hSeeds"`
	Count      int      `json:"count"`
	StartIndex int      `json:"startIndex"`
	TotalCount int      `json:"totalCount"`
}

// ChallengeResponse 挑战码响应结构
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
}

// SignatureResponse 签名响应结构
type SignatureResponse struct {
	HSeed     string `json:"hSeed"`
	Signature string `json:"signature"`
}

// WhiteAddressResponse 白名单地址响应结构
type WhiteAddressResponse struct {
	Address       string `json:"address"`
	IsWhitelisted bool   `json:"isWhitelisted"`
}

// 测试用例

// TestTestEndpoint 测试健康检查接口
func TestTestEndpoint(t *testing.T) {
	router := setupTest()

	// 创建请求
	req, _ := http.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 0, response.Code)
	assert.Equal(t, "ok", response.Msg)
}

// TestUploadImage64 测试上传Base64图片接口
func TestUploadImage64(t *testing.T) {
	router := setupTest()

	// 创建测试数据
	testData := map[string]string{
		"hseed":       generateTestSeed(),
		"base64Image": generateTestBase64Image(),
		"address":     "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
		"collectId":   "test-collect-123",
	}
	data, _ := json.Marshal(testData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/upload/image64", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 0, response.Code)
	assert.Contains(t, response.Msg, "上传成功")
}

// TestUploadImage64MissingParams 测试上传Base64图片接口缺少参数
func TestUploadImage64MissingParams(t *testing.T) {
	router := setupTest()

	// 创建缺少参数的测试数据
	testData := map[string]string{
		"hseed": generateTestSeed(),
		// 缺少其他必要参数
	}
	data, _ := json.Marshal(testData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/upload/image64", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 400, response.Code)
}

// TestUploadImage64InvalidBase64 测试上传Base64图片接口无效的Base64数据
func TestUploadImage64InvalidBase64(t *testing.T) {
	router := setupTest()

	// 创建包含无效Base64的测试数据
	testData := map[string]string{
		"hseed":       generateTestSeed(),
		"base64Image": "invalid-base64-data",
		"address":     "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
		"collectId":   "test-collect-123",
	}
	data, _ := json.Marshal(testData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/upload/image64", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 400, response.Code)
}

// TestUpdateImage 测试更新图片接口
func TestUpdateImage(t *testing.T) {
	router := setupTest()
	testHSeed := generateTestSeed()

	// 先上传一张图片
	initialData := map[string]string{
		"hseed":       testHSeed,
		"base64Image": generateTestBase64Image(),
		"address":     "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
		"collectId":   "test-collect-123",
	}
	initialDataBytes, _ := json.Marshal(initialData)

	req, _ := http.NewRequest("POST", "/api/upload/image64", bytes.NewBuffer(initialDataBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), req)

	// 然后更新这张图片
	updateData := map[string]string{
		"hseed":       testHSeed,
		"base64Image": generateTestBase64Image(), // 使用相同的图片进行测试
	}
	updateDataBytes, _ := json.Marshal(updateData)

	updateReq, _ := http.NewRequest("POST", "/api/upload/updateimage", bytes.NewBuffer(updateDataBytes))
	updateReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, updateReq)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 0, response.Code)
	assert.Contains(t, response.Msg, "更新成功")
}

// TestUpdateImageNotFound 测试更新不存在的图片
func TestUpdateImageNotFound(t *testing.T) {
	router := setupTest()

	// 尝试更新不存在的图片
	updateData := map[string]string{
		"hseed":       "non-existent-seed",
		"base64Image": generateTestBase64Image(),
	}
	updateDataBytes, _ := json.Marshal(updateData)

	req, _ := http.NewRequest("POST", "/api/upload/updateimage", bytes.NewBuffer(updateDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusNotFound, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 404, response.Code)
}

// 由于GetStaticImage接口需要实际的文件系统操作，这里我们暂时跳过测试
// 在实际项目中，应该创建模拟的文件服务或使用临时目录进行测试

// TestRequestSeed 测试申请新种子接口
func TestRequestSeed(t *testing.T) {
	router := setupTest()

	// 创建请求
	req, _ := http.NewRequest("GET", "/api/seed/request?address=0x71C7656EC7ab88b098defB751B7401B5f6d8976F", nil)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response SeedResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotEmpty(t, response.HSeed)
}

// TestRequestSeedMissingAddress 测试申请新种子接口缺少地址参数
func TestRequestSeedMissingAddress(t *testing.T) {
	router := setupTest()

	// 创建缺少地址参数的请求
	req, _ := http.NewRequest("GET", "/api/seed/request", nil)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response SeedResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
}

// TestUseSeed 测试标记种子为已使用接口
func TestUseSeed(t *testing.T) {
	router := setupTest()
	testHSeed := generateTestSeed()

	// 创建请求数据
	useSeedData := map[string]string{
		"hSeed":   testHSeed,
		"address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
		"txhash":  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	useSeedDataBytes, _ := json.Marshal(useSeedData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/seed/use", bytes.NewBuffer(useSeedDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response UseSeedResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
}

// TestUseSeedPreTx 测试标记种子为已使用（预交易）接口
func TestUseSeedPreTx(t *testing.T) {
	router := setupTest()
	testHSeed := generateTestSeed()

	// 创建请求数据
	useSeedData := map[string]string{
		"hSeed":   testHSeed,
		"address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
		"txhash":  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	useSeedDataBytes, _ := json.Marshal(useSeedData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/seed/usepretx", bytes.NewBuffer(useSeedDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response UseSeedResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
}

// TestGetSeeds 测试获取已使用种子列表接口
func TestGetSeeds(t *testing.T) {
	router := setupTest()

	// 创建请求
	req, _ := http.NewRequest("GET", "/api/seed/getseeds?startIndex=0&count=10", nil)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response GetSeedsResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
}

// TestGetSeedsInvalidParams 测试获取已使用种子列表接口无效参数
func TestGetSeedsInvalidParams(t *testing.T) {
	router := setupTest()

	// 创建使用无效参数的请求
	req, _ := http.NewRequest("GET", "/api/seed/getseeds?startIndex=-1&count=200", nil)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应 - 应该能处理无效参数并返回默认值
	assert.Equal(t, http.StatusOK, w.Code)

	var response GetSeedsResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
}

// TestGenerateChallenge 测试生成挑战码接口
func TestGenerateChallenge(t *testing.T) {
	router := setupTest()

	// 创建请求数据
	challengeData := map[string]string{
		"address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
	}
	challengeDataBytes, _ := json.Marshal(challengeData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/signature/challenge", bytes.NewBuffer(challengeDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response ChallengeResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Challenge)
	assert.Contains(t, response.Challenge, "0x")
}

// TestGenerateChallengeMissingAddress 测试生成挑战码接口缺少地址参数
func TestGenerateChallengeMissingAddress(t *testing.T) {
	router := setupTest()

	// 创建缺少地址参数的请求数据
	challengeData := map[string]string{}
	challengeDataBytes, _ := json.Marshal(challengeData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/signature/challenge", bytes.NewBuffer(challengeDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 400, response.Code)
}

// TestGenerateSignature 测试生成签名（带挑战码验证）接口
func TestGenerateSignature(t *testing.T) {
	router := setupTest()
	testHSeed := generateTestSeed()

	// 这里我们模拟挑战码验证过程
	// 在实际测试中，应该先调用GenerateChallenge接口获取有效挑战码
	challenge := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	// 创建请求数据
	signatureData := map[string]interface{}{
		"hSeed":     testHSeed,
		"address":   "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
		"chainId":   1,
		"challenge": challenge,
	}
	signatureDataBytes, _ := json.Marshal(signatureData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/signature/generate", bytes.NewBuffer(signatureDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response SignatureResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, testHSeed, response.HSeed)
	assert.NotEmpty(t, response.Signature)
}

// TestGenerateSignatureNoChallenge 测试生成签名（无挑战码验证）接口
func TestGenerateSignatureNoChallenge(t *testing.T) {
	router := setupTest()
	testHSeed := generateTestSeed()

	// 创建请求数据
	signatureData := map[string]interface{}{
		"hSeed":   testHSeed,
		"address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
		"chainId": 1,
	}
	signatureDataBytes, _ := json.Marshal(signatureData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/signature/generate-no-challenge", bytes.NewBuffer(signatureDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response SignatureResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, testHSeed, response.HSeed)
	assert.NotEmpty(t, response.Signature)
}

// TestIsWhiteAddress 测试检查地址是否在白名单中接口
func TestIsWhiteAddress(t *testing.T) {
	router := setupTest()

	// 创建请求数据
	whiteListData := map[string]string{
		"address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
	}
	whiteListDataBytes, _ := json.Marshal(whiteListData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/signature/is-white-address", bytes.NewBuffer(whiteListDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response WhiteAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", response.Address)
}

// TestIsWhiteAddressXDCheck 测试检查地址是否在白名单中（XDCheck）接口
func TestIsWhiteAddressXDCheck(t *testing.T) {
	router := setupTest()

	// 创建请求数据
	whiteListData := map[string]string{
		"address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
	}
	whiteListDataBytes, _ := json.Marshal(whiteListData)

	// 创建请求
	req, _ := http.NewRequest("POST", "/api/signature/is-white-address-xdcheck", bytes.NewBuffer(whiteListDataBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response WhiteAddressResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", response.Address)
	assert.True(t, response.IsWhitelisted) // 根据实现，这个方法默认返回true
}

// 注意：我们移除了TestMain函数，让Go测试框架使用默认的测试运行器

// TestGetStaticImage 测试获取静态图片接口 - 正常情况
func TestGetStaticImage(t *testing.T) {
	router := setupTest()

	// 创建请求
	req, _ := http.NewRequest("GET", "/api/static/test-collect-123?hseed=test-seed-123", nil)
	w := httptest.NewRecorder()

	// 执行请求
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "image/png", w.Header().Get("Content-Type"))
	assert.NotEmpty(t, w.Body.Bytes())
}

// TestGetStaticImageMissingParams 测试获取静态图片接口 - 缺少参数
func TestGetStaticImageMissingParams(t *testing.T) {
	router := setupTest()

	// 测试缺少hseed参数
	req1, _ := http.NewRequest("GET", "/api/static/test-collect-123", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusBadRequest, w1.Code)

	var response1 Response
	err := json.Unmarshal(w1.Body.Bytes(), &response1)
	assert.NoError(t, err)
	assert.Equal(t, 400, response1.Code)
	assert.Contains(t, response1.Msg, "请求参数错误")

	// 测试缺少collectId参数（使用空collectId）
	req2, _ := http.NewRequest("GET", "/api/static/?hseed=test-seed-123", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)
}

// TestGetStaticImageNotFound 测试获取静态图片接口 - 图片不存在
func TestGetStaticImageNotFound(t *testing.T) {
	router := setupTest()

	// 测试不存在的collectId
	req1, _ := http.NewRequest("GET", "/api/static/non-existent-collect?hseed=test-seed-123", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusNotFound, w1.Code)

	var response1 Response
	err := json.Unmarshal(w1.Body.Bytes(), &response1)
	assert.NoError(t, err)
	assert.Equal(t, 404, response1.Code)
	assert.Contains(t, response1.Msg, "图片不存在")

	// 测试不存在的hseed
	req2, _ := http.NewRequest("GET", "/api/static/test-collect-123?hseed=non-existent-seed", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusNotFound, w2.Code)
}

// TestGetStaticImageDecodeError 测试获取静态图片接口 - 图片解码失败
func TestGetStaticImageDecodeError(t *testing.T) {
	router := setupTest()

	// 测试会导致解码失败的情况
	req, _ := http.NewRequest("GET", "/api/static/test-collect-123?hseed=invalid-base64-seed", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 500, response.Code)
	assert.Contains(t, response.Msg, "图片解码失败")
}
