package models

import (
	"github.com/user/go-nft/config"
)

// AutoMigrate 自动迁移数据库表结构
func AutoMigrate() error {
	db := config.GetDB()

	// 创建collection_images表
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS collection_images (
		id INT AUTO_INCREMENT PRIMARY KEY,
		hseed VARCHAR(255) NOT NULL,
		collect_id VARCHAR(255) NOT NULL,
		image_base64 LONGTEXT NOT NULL,
		address VARCHAR(255) NOT NULL,
		update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY idx_hseed (hseed)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
	`)
	if err != nil {
		return err
	}

	// 创建seed_order表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS seed_order (
		id INT AUTO_INCREMENT PRIMARY KEY,
		address VARCHAR(255) NOT NULL,
		hSeed VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY idx_hseed (hSeed)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
	`)
	if err != nil {
		return err
	}

	// 创建seed_used表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS seed_used (
		id INT AUTO_INCREMENT PRIMARY KEY,
		address VARCHAR(255) NOT NULL,
		hSeed VARCHAR(255) NOT NULL,
		txhash VARCHAR(255) NOT NULL,
		state TINYINT DEFAULT 1,
		image_id INT,
		update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE KEY idx_hseed (hSeed)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
	`)
	if err != nil {
		return err
	}

	// 创建seed_used_pretx表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS seed_used_pretx (
		id INT AUTO_INCREMENT PRIMARY KEY,
		address VARCHAR(255) NOT NULL,
		hSeed VARCHAR(255) NOT NULL,
		txhash VARCHAR(255) NOT NULL,
		state TINYINT DEFAULT 1,
		image_id INT,
		update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE KEY idx_hseed (hSeed)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
	`)
	if err != nil {
		return err
	}

	// 创建whitelist_usage表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS whitelist_usage (
		id INT AUTO_INCREMENT PRIMARY KEY,
		wallet_address VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE KEY idx_wallet_address (wallet_address)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
	`)
	if err != nil {
		return err
	}

	// 创建challenge_codes表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS challenge_codes (
		id INT AUTO_INCREMENT PRIMARY KEY,
		challenge_code VARCHAR(255) NOT NULL,
		wallet_address VARCHAR(255) NOT NULL,
		ip_address VARCHAR(50) NOT NULL,
		is_used BOOLEAN DEFAULT FALSE,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_wallet_address (wallet_address),
		INDEX idx_ip_address (ip_address),
		INDEX idx_expires_at (expires_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
	`)
	if err != nil {
		return err
	}

	return nil
}