package config

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

// InitDB 初始化数据库连接
func InitDB() error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}

	// 设置连接池参数
	DB.SetMaxIdleConns(10)
	DB.SetMaxOpenConns(100)
	DB.SetConnMaxLifetime(time.Hour)

	// 测试连接
	if err := DB.Ping(); err != nil {
		return err
	}

	return nil
}

// GetDB 获取数据库连接
func GetDB() *sql.DB {
	return DB
}