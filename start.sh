#!/bin/bash

# 设置Go代理
export GOPROXY=https://goproxy.cn,direct

# 检查是否存在.env文件，如果不存在则从.env.example复制
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "已从.env.example创建.env文件，请根据需要修改配置"
    else
        echo "警告：未找到.env或.env.example文件，请确保已正确配置环境变量"
    fi
fi

# 下载依赖
echo "正在下载依赖..."
go mod download

# 运行服务
echo "正在启动服务..."
go run main.go