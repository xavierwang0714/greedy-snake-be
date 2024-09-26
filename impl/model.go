package impl

import (
	"database/sql"
	"sync"
	"time"
)

const (
	HOST     = "snake_pg"
	PORT     = "5432"
	USER     = "postgres"
	PASSWORD = "766515"
	DBNAME   = "greedy_snake_db"
)

var db *sql.DB

var (
	mu          sync.Mutex                   // 互斥锁，用于保护在线用户映射
	onlineUsers = make(map[string]time.Time) // 存储每个用户的在线状态
)

type UserSessionID struct {
	SessionID string `json:"SessionID"`
}

// UserGameData 存储用户游戏数据的结构体
type UserGameData struct {
	LastLength int `json:"LastLength"`
	LastScore  int `json:"LastScore"`
	BestLength int `json:"BestLength"`
	BestScore  int `json:"BestScore"`
}

type UserGameDataWithUsername struct {
	Username   string `json:"Username"`
	LastLength int    `json:"LastLength"`
	LastScore  int    `json:"LastScore"`
	BestLength int    `json:"BestLength"`
	BestScore  int    `json:"BestScore"`
}

// UserCredentials 结构体用于解析接收到的用户名和密码
type UserCredentials struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}
