package models

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/user/go-nft/config"
)

// CollectionImage 收藏品图片模型
type CollectionImage struct {
	ID         int    `json:"id"`
	HSeed      string `json:"hseed"`
	CollectID  string `json:"collect_id"`
	ImageBase64 string `json:"image_base64"`
	Address    string `json:"address"`
	UpdateTime time.Time `json:"update_time"`
}

// SeedOrder 种子订单模型
type SeedOrder struct {
	ID        int       `json:"id"`
	Address   string    `json:"address"`
	HSeed     string    `json:"hSeed"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SeedUsed 已使用种子模型
type SeedUsed struct {
	ID        int       `json:"id"`
	Address   string    `json:"address"`
	HSeed     string    `json:"hSeed"`
	TxHash    string    `json:"txhash"`
	State     int       `json:"state"`
	ImageID   sql.NullInt64 `json:"image_id"`
	UpdateAt  time.Time `json:"update_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ChallengeCode 挑战码模型
type ChallengeCode struct {
	ID            int       `json:"id"`
	ChallengeCode string    `json:"challenge_code"`
	WalletAddress string    `json:"wallet_address"`
	IPAddress     string    `json:"ip_address"`
	IsUsed        bool      `json:"is_used"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// WhitelistUsage 白名单使用记录模型
type WhitelistUsage struct {
	ID            int       `json:"id"`
	WalletAddress string    `json:"wallet_address"`
	CreatedAt     time.Time `json:"created_at"`
}

// 创建或更新图片
func CreateOrUpdateImage(img *CollectionImage) error {
	db := config.GetDB()
	query := `
	INSERT INTO collection_images (hseed, collect_id, image_base64, address) 
	VALUES (?, ?, ?, ?) 
	ON DUPLICATE KEY UPDATE 
		collect_id = VALUES(collect_id), 
		image_base64 = VALUES(image_base64), 
		address = VALUES(address), 
		update_time = CURRENT_TIMESTAMP
	`
	_, err := db.Exec(query, img.HSeed, img.CollectID, img.ImageBase64, img.Address)
	return err
}

// 根据hseed获取图片
func GetImageByHSeed(hseed string) (*CollectionImage, error) {
	db := config.GetDB()
	img := &CollectionImage{}
	query := `SELECT id, hseed, collect_id, image_base64, address, update_time FROM collection_images WHERE hseed = ?`
	err := db.QueryRow(query, hseed).Scan(&img.ID, &img.HSeed, &img.CollectID, &img.ImageBase64, &img.Address, &img.UpdateTime)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// 根据collectId和hseed获取图片
func GetImageByCollectIDAndHSeed(collectId, hseed string) (*CollectionImage, error) {
	db := config.GetDB()
	img := &CollectionImage{}
	query := `SELECT id, hseed, collect_id, image_base64, address, update_time FROM collection_images WHERE collect_id = ? AND hseed = ?`
	err := db.QueryRow(query, collectId, hseed).Scan(&img.ID, &img.HSeed, &img.CollectID, &img.ImageBase64, &img.Address, &img.UpdateTime)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// 创建种子订单
func CreateSeedOrder(order *SeedOrder) error {
	db := config.GetDB()
	query := `INSERT INTO seed_order (address, hSeed) VALUES (?, ?)`
	_, err := db.Exec(query, order.Address, order.HSeed)
	return err
}

// 检查种子是否已存在
func IsSeedExists(hseed string) (bool, error) {
	db := config.GetDB()
	var count int
	query := `SELECT COUNT(*) FROM seed_order WHERE hSeed = ?`
	err := db.QueryRow(query, hseed).Scan(&count)
	return count > 0, err
}

// 标记种子为已使用
func MarkSeedAsUsed(seedUsed *SeedUsed) error {
	db := config.GetDB()
	query := `INSERT INTO seed_used (address, hSeed, txhash, state) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE txhash = VALUES(txhash), state = VALUES(state)`
	_, err := db.Exec(query, seedUsed.Address, seedUsed.HSeed, seedUsed.TxHash, seedUsed.State)
	return err
}

// 标记预交易种子为已使用
func MarkSeedAsUsedPreTx(seedUsed *SeedUsed) error {
	db := config.GetDB()
	query := `INSERT INTO seed_used_pretx (address, hSeed, txhash, state) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE txhash = VALUES(txhash), state = VALUES(state)`
	_, err := db.Exec(query, seedUsed.Address, seedUsed.HSeed, seedUsed.TxHash, seedUsed.State)
	return err
}

// 获取已使用的种子列表
func GetUsedSeeds(startIndex, count int) ([]string, int, error) {
	db := config.GetDB()
	
	// 获取总数
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM seed_used WHERE state = 1`
	err := db.QueryRow(countQuery).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}
	
	// 获取分页数据
	seeds := []string{}
	query := `SELECT hSeed FROM seed_used WHERE state = 1 ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := db.Query(query, count, startIndex)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	
	for rows.Next() {
		var hseed string
		if err := rows.Scan(&hseed); err != nil {
			return nil, 0, err
		}
		seeds = append(seeds, hseed)
	}
	
	return seeds, totalCount, nil
}

// 创建挑战码
func CreateChallengeCode(challenge *ChallengeCode) error {
	db := config.GetDB()
	query := `INSERT INTO challenge_codes (challenge_code, wallet_address, ip_address, expires_at) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, challenge.ChallengeCode, challenge.WalletAddress, challenge.IPAddress, challenge.ExpiresAt)
	return err
}

// 验证挑战码
func VerifyChallengeCode(challengeCode, walletAddress string) (bool, error) {
	db := config.GetDB()
	query := `SELECT COUNT(*) FROM challenge_codes WHERE challenge_code = ? AND wallet_address = ? AND is_used = false AND expires_at > NOW()`
	var count int
	err := db.QueryRow(query, challengeCode, walletAddress).Scan(&count)
	if err != nil {
		return false, err
	}
	
	// 标记为已使用
	if count > 0 {
		updateQuery := `UPDATE challenge_codes SET is_used = true WHERE challenge_code = ? AND wallet_address = ?`
		_, err = db.Exec(updateQuery, challengeCode, walletAddress)
		if err != nil {
			return false, err
		}
	}
	
	return count > 0, nil
}

// 检查频率限制
func CheckRateLimit(ipAddress, walletAddress string) (bool, error) {
	db := config.GetDB()
	
	// 检查IP限制（每天最多500次）
	var ipCount int
	ipQuery := `SELECT COUNT(*) FROM challenge_codes WHERE ip_address = ? AND DATE(created_at) = DATE(NOW())`
	err := db.QueryRow(ipQuery, ipAddress).Scan(&ipCount)
	if err != nil {
		return false, err
	}
	if ipCount >= 500 {
		return false, fmt.Errorf("IP rate limit exceeded")
	}
	
	// 检查钱包地址限制（每天最多20次）
	var addressCount int
	addressQuery := `SELECT COUNT(*) FROM challenge_codes WHERE wallet_address = ? AND DATE(created_at) = DATE(NOW())`
	err = db.QueryRow(addressQuery, walletAddress).Scan(&addressCount)
	if err != nil {
		return false, err
	}
	if addressCount >= 20 {
		return false, fmt.Errorf("wallet address rate limit exceeded")
	}
	
	return true, nil
}

// 检查地址是否在白名单中且未被使用
func IsAddressInWhitelist(address string) (bool, error) {
	db := config.GetDB()
	var count int
	// 假设白名单地址存储在某个表中，这里简化处理
	// 实际应用中应该从专门的白名单表中查询
	query := `SELECT COUNT(*) FROM whitelist_usage WHERE wallet_address = ?`
	err := db.QueryRow(query, address).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	// 这里简化处理，实际应该查询白名单表并检查是否未使用
	return count == 0, nil
}

// 检查地址是否在白名单中（不检查使用状态）
func IsAddressInWhitelistXDCheck(address string) (bool, error) {
	// 实际应用中应该从专门的白名单表中查询
	// 这里简化处理，返回true表示在白名单中
	return true, nil
}