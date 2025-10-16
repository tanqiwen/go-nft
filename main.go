package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/user/go-nft/config"
	"github.com/user/go-nft/controllers"
	"github.com/user/go-nft/middlewares"
	"github.com/user/go-nft/models"
)

func main() {
	// 加载环境变量
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	// 初始化数据库连接
	if err := config.InitDB(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// 自动迁移数据库表
	if err := models.AutoMigrate(); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// 设置Gin模式
	gin.SetMode(gin.ReleaseMode)

	// 创建Gin实例
	r := gin.Default()

	// 注册中间件
	r.Use(middlewares.CORS())
	r.Use(middlewares.RateLimit())

	// 静态文件路由
	r.Static("/static", "./static")

	// API路由组
	api := r.Group("/api")
	{
		// 测试接口
		api.GET("/test", controllers.Test)

		// 图片相关接口
		imageGroup := api.Group("/upload")
		{
			imageGroup.POST("/image64", controllers.UploadImage64)
			imageGroup.POST("/updateimage", controllers.UpdateImage)
		}
		api.GET("/static/:collectId", controllers.GetStaticImage)

		// 种子管理接口
		seedGroup := api.Group("/seed")
		{
			seedGroup.GET("/request", controllers.RequestSeed)
			seedGroup.POST("/use", controllers.UseSeed)
			seedGroup.POST("/usepretx", controllers.UseSeedPreTx)
			seedGroup.GET("/getseeds", controllers.GetSeeds)
		}

		// 签名验证接口
		signatureGroup := api.Group("/signature")
		{
			signatureGroup.POST("/challenge", controllers.GenerateChallenge)
			signatureGroup.POST("/generate", controllers.GenerateSignature)
			signatureGroup.POST("/generate-no-challenge", controllers.GenerateSignatureNoChallenge)
			signatureGroup.POST("/is-white-address", controllers.IsWhiteAddress)
			signatureGroup.POST("/is-white-address-xdcheck", controllers.IsWhiteAddressXDCheck)
		}
	}

	// 启动服务器
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8000"
	}

	log.Printf("Server starting on port %s", port)
	if err := r.Run(fmt.Sprintf(":%s", port)); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}