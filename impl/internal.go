package impl

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	_ "github.com/lib/pq"
)

func init() {
	initDB()
}

// initDB 连接数据库
func initDB() {
	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", HOST, PORT, USER, PASSWORD, DBNAME)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connect to DB successfully!")
}

func enableCORS(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://snake.abtxw.com")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
}

// sessionHandler 处理会话请求
func sessionHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w)

	log.Println("sessionHandler: Received request")

	// 检查请求中是否包含会话cookie
	cookie, err := getCookie(r, "session_id")

	if err != nil || cookie.Value == "" {
		log.Println("sessionHandler: No session_id cookie found, creating new session")

		// 如果没有会话cookie，创建一个新的会话
		newSessionID := uuid.New().String()

		// 构建插入数据库的SQL语句
		sqlStatement := `
            INSERT INTO unregistered_user_table (session_id, last_length, last_score, best_length, best_score)
            VALUES ($1, $2, $3, $4, $5)`

		// 将新的会话ID和初始值插入到数据库中，并初始化其他游戏数据为零
		_, err := db.Exec(sqlStatement, newSessionID, 0, 0, 0, 0)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			log.Println("sessionHandler: Error inserting new session:", err)
			return
		}

		// 创建cookie并发送给前端
		http.SetCookie(w, &http.Cookie{
			Name:       "session_id",
			Value:      newSessionID,
			Path:       "/",
			Domain:     "abtxw.com",
			Expires:    time.Now().Add(86400 * time.Second),
			RawExpires: "",
			MaxAge:     86400,
			Secure:     false,
			HttpOnly:   false,
			SameSite:   http.SameSiteLaxMode,
			Raw:        "",
			Unparsed:   nil,
		})

		log.Println("sessionHandler: New session created, session_id:", newSessionID)
	} else {
		log.Println("sessionHandler: Existing session_id cookie found:", cookie.Value)

		// 如果有会话cookie，恢复会话
		sessionID := cookie.Value

		// 构建查询数据库的SQL语句
		sqlStatement := `
		SELECT last_length, last_score, best_length, best_score 
		FROM unregistered_user_table 
		WHERE session_id = $1`

		// 查询数据库
		var gameData UserGameData
		err := db.QueryRow(sqlStatement, sessionID).Scan(&gameData.LastLength, &gameData.LastScore, &gameData.BestLength, &gameData.BestScore)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// 没有找到对应的记录
				http.Error(w, "Session not found", http.StatusNotFound)
			} else {
				// 数据库查询错误
				http.Error(w, "Database error", http.StatusInternalServerError)
			}
			log.Println("sessionHandler: Error retrieving session data:", err)
			return
		}

		log.Println("sessionHandler: unregistered gameData", gameData)

		// 将游戏数据以JSON格式发送回客户端
		jsonResponse, err := json.Marshal(gameData)
		if err != nil {
			http.Error(w, "Error creating response", http.StatusInternalServerError)
			log.Println("sessionHandler: Error marshaling game data:", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(jsonResponse)
		if err != nil {
			log.Printf("sessionHandler: Error writing response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		log.Println("sessionHandler: Session data retrieved successfully")
	}
}

// unregisteredSaveGameDataHandler 处理游戏数据保存的请求
func unregisteredSaveGameDataHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("unregisteredSaveGameDataHandler: Received request")

	var data UserGameData

	log.Println("unregisteredSaveGameDataHandler-r.Body: ", r.Body) // 用于测试

	// 解析请求体为JSON
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println("unregisteredSaveGameDataHandler: Decode JSON failed")
		return
	}

	log.Println("unregisteredSaveGameDataHandler: Received game data:", data) // 用于测试

	// 获取会话ID
	sessionCookie, err := getCookie(r, "session_id")
	if err != nil {
		http.Error(w, "Session cookie not found", http.StatusBadRequest)
		log.Println("unregisteredSaveGameDataHandler: Session cookie not found")
		return
	} else {
		log.Println("unregisteredSaveGameDataHandler: Receive session cookie successfully. Session cookie: ", sessionCookie)
	}

	// 更新数据库中的游戏数据
	var sqlStatement string
	if data.BestLength == -1 && data.BestScore == -1 {
		// 不更新最佳长度和分数
		sqlStatement = `
            UPDATE unregistered_user_table
            SET last_length = $2, last_score = $3
            WHERE session_id = $1`
		_, err = db.Exec(sqlStatement, sessionCookie.Value, data.LastLength, data.LastScore)
	} else if data.BestLength == -1 && data.BestScore != -1 {
		// 不更新最佳长度
		sqlStatement = `
            UPDATE unregistered_user_table
            SET last_length = $2, last_score = $3, best_score = $4
            WHERE session_id = $1`
		_, err = db.Exec(sqlStatement, sessionCookie.Value, data.LastLength, data.LastScore, data.BestScore)
	} else if data.BestLength != -1 && data.BestScore == -1 {
		// 不更新最佳分数
		sqlStatement = `
            UPDATE unregistered_user_table
            SET last_length = $2, last_score = $3, best_length = $4
            WHERE session_id = $1`
		_, err = db.Exec(sqlStatement, sessionCookie.Value, data.LastLength, data.LastScore, data.BestLength)
	} else {
		// 更新所有字段
		sqlStatement = `
            UPDATE unregistered_user_table
            SET last_length = $2, last_score = $3, best_length = $4, best_score = $5
            WHERE session_id = $1`
		_, err = db.Exec(sqlStatement, sessionCookie.Value, data.LastLength, data.LastScore, data.BestLength, data.BestScore)
	}

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Println("unregisteredSaveGameDataHandler: Error updating session data:", err)
		return
	}

	log.Println("unregisteredSaveGameDataHandler: Game data updated successfully")
}

// 处理登录后用户的游戏数据保存
func registeredSaveGameDataHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("regSaveGameDataHandler: Received request")

	var data UserGameDataWithUsername

	log.Println("regSaveGameDataHandler-r.Body: ", r.Body) // 用于测试

	// 解析请求体为JSON
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println("regSaveGameDataHandler: Decode JSON failed")
		return
	}

	log.Println("regSaveGameDataHandler: Received game data:", data) // 用于测试

	// 更新数据库中的游戏数据
	var sqlStatement string
	var err error
	if data.BestLength == -1 && data.BestScore == -1 {
		// 不更新最佳长度和分数
		sqlStatement = `
            UPDATE registered_user_table
            SET last_length = $2, last_score = $3
            WHERE username = $1`
		_, err = db.Exec(sqlStatement, data.Username, data.LastLength, data.LastScore)
	} else if data.BestLength == -1 && data.BestScore != -1 {
		// 不更新最佳长度
		sqlStatement = `
            UPDATE registered_user_table
            SET last_length = $2, last_score = $3, best_score = $4
            WHERE username = $1`
		_, err = db.Exec(sqlStatement, data.Username, data.LastLength, data.LastScore, data.BestScore)
	} else if data.BestLength != -1 && data.BestScore == -1 {
		// 不更新最佳分数
		sqlStatement = `
            UPDATE registered_user_table
            SET last_length = $2, last_score = $3, best_length = $4
            WHERE username = $1`
		_, err = db.Exec(sqlStatement, data.Username, data.LastLength, data.LastScore, data.BestLength)
	} else {
		// 更新所有字段
		sqlStatement = `
            UPDATE registered_user_table
            SET last_length = $2, last_score = $3, best_length = $4, best_score = $5
            WHERE username = $1`
		_, err = db.Exec(sqlStatement, data.Username, data.LastLength, data.LastScore, data.BestLength, data.BestScore)
	}

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Println("regSaveGameDataHandler: Error updating session data:", err)
		return
	}

	log.Println("regSaveGameDataHandler: Game data updated successfully")
}

// 处理用户登录
func loginHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("loginHandler: Received request")

	if r.Method == http.MethodPost {
		var credentials UserCredentials

		// 解析请求体为JSON
		if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			log.Println("loginHandler: Decode JSON failed")
			return
		}

		log.Println("loginHandler: Received credentials: ", credentials)

		// TODO: 检查前端传入的账号密码是否为空

		// 在用户成功登录之前检查该用户是否已经在线
		//mu.Lock()
		//_, userAlreadyOnline := onlineUsers[credentials.Username]
		//mu.Unlock()
		userAlreadyOnline := false

		if userAlreadyOnline {
			log.Println("loginHandler: User is already logged in")

			// 用户已经在线，返回登录失败的消息
			response := map[string]string{"message": "User is already logged in"}
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Println("loginHandler: Internal Server Error")
				return
			}

			// 输出在线用户列表用于测试
			log.Println("loginHandler: onlineUsers: ", onlineUsers)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, err = w.Write(jsonResponse)
			if err != nil {
				log.Printf("loginHandler: Error writing response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}

		// 进行用户名和密码的验证
		userExists, err := checkUserExistsInDB(credentials.Username)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			log.Println("loginHandler: Database error")
			return
		}

		if userExists {
			// 用户存在，检查密码是否正确
			passwordCorrect, err := checkPasswordCorrectInDB(credentials.Username, credentials.Password)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				log.Println("loginHandler: Database error")
				return
			}

			if passwordCorrect {
				log.Println("loginHandler: User login successfully")

				// 将用户标记为在线
				//mu.Lock()
				//onlineUsers[credentials.Username] = time.Now()
				//mu.Unlock()

				// 输出在线用户列表用于测试
				//log.Println("loginHandler: onlineUsers: ", onlineUsers)

				// 密码正确，返回登录成功消息
				response := map[string]string{"message": "Login successful"}
				jsonResponse, err := json.Marshal(response)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					log.Println("loginHandler: Internal Server Error")
					return
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, err = w.Write(jsonResponse)
				if err != nil {
					log.Printf("loginHandler: Error writing response: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			} else {
				log.Println("loginHandler: Incorrect password, login unsuccessfully")

				// 密码错误
				response := map[string]string{"message": "Incorrect password"}
				jsonResponse, err := json.Marshal(response)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					log.Println("loginHandler: Internal Server Error")
					return
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, err = w.Write(jsonResponse)
				if err != nil {
					return
				}
			}
		} else {
			// 用户不存在，创建用户
			// 将用户名和密码插入到reg_user_table的操作
			err := createUserInDB(credentials.Username, credentials.Password)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				log.Println("loginHandler: Database error")
				return
			}

			log.Println("loginHandler: create a new user successfully")

			// 将用户标记为在线
			mu.Lock()
			onlineUsers[credentials.Username] = time.Now()
			mu.Unlock()

			// 输出在线用户列表用于测试
			log.Println("loginHandler: onlineUsers: ", onlineUsers)

			// 返回创建用户成功消息
			response := map[string]string{"message": "User created successfully"}
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Println("loginHandler: Internal Server Error")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(jsonResponse)
			if err != nil {
				log.Printf("loginHandler: Error writing response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		log.Println("loginHandler: Method not allowed")
	}
}

// 创建用户并初始化游戏数据
func createUserInDB(username, password string) error {
	// 在这里添加将用户名和密码插入到reg_user_table的SQL语句
	sqlStatement := `
        INSERT INTO registered_user_table (username, password, last_length, last_score, best_length, best_score)
        VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := db.Exec(sqlStatement, username, password, 0, 0, 0, 0)
	return err
}

// 检查用户是否存在于数据库中
func checkUserExistsInDB(username string) (bool, error) {
	sqlStatement := `
		SELECT EXISTS (SELECT 1 FROM registered_user_table WHERE username = $1)`

	var exists bool
	err := db.QueryRow(sqlStatement, username).Scan(&exists)
	if err != nil {
		log.Println("checkUserExistsInDB: check user exists in DB failed")
		return false, err
	}

	log.Println("checkUserExistsInDB: is user exists: ", exists)

	return exists, nil
}

// 检查密码是否正确
func checkPasswordCorrectInDB(username, password string) (bool, error) {
	sqlStatement := `
		SELECT password FROM registered_user_table WHERE username = $1`

	var storedPassword string
	err := db.QueryRow(sqlStatement, username).Scan(&storedPassword)
	if err != nil {
		log.Println("checkPasswordCorrectInDB: check password correct in DB failed")
		return false, err
	}

	log.Println("checkPasswordCorrectInDB: is password correct: ", storedPassword == password)

	// 检查密码是否正确
	return storedPassword == password, nil
}

// 处理已登录用户获取游戏数据
func fetchGameDataHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("fetchGameDataHandler: Received request")

	var userCredential UserCredentials

	// 解析请求体为JSON
	if err := json.NewDecoder(r.Body).Decode(&userCredential); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println("fetchGameDataHandler: Decode JSON failed")
		return
	}

	// 构建查询数据库的SQL语句
	sqlStatement := `
		SELECT last_length, last_score, best_length, best_score 
		FROM registered_user_table 
		WHERE username = $1`

	// 查询数据库
	var gameData UserGameData
	err := db.QueryRow(sqlStatement, userCredential.Username).Scan(&gameData.LastLength, &gameData.LastScore, &gameData.BestLength, &gameData.BestScore)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 没有找到对应的记录
			http.Error(w, "User data not found", http.StatusNotFound)
			log.Println("fetchGameDataHandler: User data not found")
		} else {
			// 数据库查询错误
			http.Error(w, "Database error", http.StatusInternalServerError)
			log.Println("fetchGameDataHandler: Database error")
		}
		log.Println("fetchGameDataHandler: Error retrieving user game data:", err)
		return
	}

	// 将游戏数据以JSON格式发送回客户端
	jsonResponse, err := json.Marshal(gameData)
	if err != nil {
		http.Error(w, "Error creating response", http.StatusInternalServerError)
		log.Println("fetchGameDataHandler: Error marshaling game data:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonResponse)
	if err != nil {
		log.Printf("fetchGameDataHandler: Error writing response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println("fetchGameDataHandler: Game data retrieved successfully")
}

// 处理心跳信号
func heartBeatHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("heartBeatHandler: Received heartbeat")

	var userCredential UserCredentials

	// 解析请求体为JSON
	if err := json.NewDecoder(r.Body).Decode(&userCredential); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println("heartBeatHandler: Decode JSON failed")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// 更新用户的最后一次心跳时间
	onlineUsers[userCredential.Username] = time.Now()
	log.Println("heartbeatHandler: onlineUsers: ", onlineUsers)

	// 返回成功的响应
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("Heartbeat received successfully"))
	if err != nil {
		log.Printf("heartBeatHandler: Error writing response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println("heartBeatHandler: Heartbeat processed successfully")
}

func cleanupOnlineUsers() {
	for {
		time.Sleep(time.Minute) // 间隔一分钟执行一次检查

		mu.Lock()
		for username, lastHeartbeat := range onlineUsers {
			if time.Since(lastHeartbeat) > time.Minute*5 { // 假设5分钟未收到心跳信号就认为用户离线
				delete(onlineUsers, username)
				log.Printf("User %s is considered offline\n", username)
			}
		}
		mu.Unlock()
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("logoutHandler: Received request")

	if r.Method == http.MethodPost {
		var credentials UserCredentials

		// 解析请求体为JSON
		if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			log.Println("loginHandler: Decode JSON failed")
			return
		}

		log.Println("logoutHandler: Received credentials: ", credentials)

		// 将用户从在线列表中移除
		mu.Lock()
		delete(onlineUsers, credentials.Username)
		mu.Unlock()

		log.Println("logoutHandler: onlineUsers: ", onlineUsers)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		log.Println("logoutHandler: Method not allowed")
	}
}

func setCookie(w http.ResponseWriter, name, value string) {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: false,
		Domain:   "localhost",
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, &cookie)
}

func getCookie(r *http.Request, name string) (*http.Cookie, error) {
	return r.Cookie(name)
}
