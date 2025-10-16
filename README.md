# Go NFT API 服务

这是一个基于Go语言实现的NFT相关API服务，提供图片上传、种子管理、签名验证和白名单验证等功能。

## 项目结构

```
go-nft/
├── config/           # 配置文件
│   └── database.go   # 数据库配置
├── controllers/      # 控制器
│   └── controllers.go # API实现
├── middlewares/      # 中间件
│   └── middlewares.go # CORS和频率限制
├── models/           # 数据模型
│   ├── migrate.go    # 数据库迁移
│   └── models.go     # 数据模型和操作
├── static/           # 静态文件目录
├── .env              # 环境变量
├── .gitignore        # Git忽略文件
├── go.mod            # Go模块文件
├── main.go           # 程序入口
└── README.md         # 项目说明
```

## 依赖项

- Gin Web框架
- MySQL数据库驱动
- godotenv环境变量管理
- crypto加密库

## 快速开始

### 1. 环境要求

- Go 1.20+
- MySQL 5.7+

### 2. 安装步骤

1. 克隆项目

```bash
git clone <repository-url>
cd go-nft
```

2. 安装依赖

```bash
go mod tidy
```

3. 配置环境变量

复制`.env`文件并修改相应的数据库连接信息：

```bash
cp .env.example .env
# 编辑.env文件
```

4. 运行项目

```bash
go run main.go
```

服务将在 `http://localhost:8000` 启动。

## API接口

### 1. 图片相关接口

- `POST /api/upload/image64` - 上传Base64图片
- `POST /api/upload/updateimage` - 更新图片
- `GET /api/static/:collectId/` - 获取静态图片

### 2. 种子管理接口

- `GET /api/seed/request` - 申请新种子
- `POST /api/seed/use` - 标记种子为已使用（铸造）
- `POST /api/seed/usepretx` - 标记种子为已使用（预交易）
- `GET /api/seed/getseeds` - 获取已使用种子列表

### 3. 签名验证接口

- `POST /api/signature/challenge` - 生成挑战码
- `POST /api/signature/generate` - 生成签名（带挑战码验证）
- `POST /api/signature/generate-no-challenge` - 生成签名（无挑战码验证）

### 4. 白名单验证接口

- `POST /api/signature/is-white-address` - 检查地址是否在白名单中且未被使用
- `POST /api/signature/is-white-address-xdcheck` - 检查地址是否在白名单中（不检查使用状态）

### 5. 测试接口

- `GET /api/test` - 服务健康检查

## 数据库表结构

服务启动时会自动创建以下表：

- `collection_images` - 收藏品图片表
- `seed_order` - 种子订单表
- `seed_used` - 已使用种子表
- `seed_used_pretx` - 预交易种子表
- `whitelist_usage` - 白名单使用记录表
- `challenge_codes` - 挑战码表

## 频率限制

- IP地址：每天最多500次挑战码生成请求
- 钱包地址：每天最多20次挑战码生成请求
- API请求：每分钟最多60次（IP维度）

## 注意事项

1. 请确保在生产环境中修改`.env`文件中的`SIGN_SECRET`为强密钥
2. 白名单功能在当前版本中是简化实现，实际使用时需要完善白名单表结构
3. 签名生成目前是模拟实现，生产环境需要使用正确的加密算法