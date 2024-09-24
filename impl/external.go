package impl

import (
	"fmt"
	"log"
	"net/http"
)

func StartHttpServer() {
	http.HandleFunc("/api/create-session", sessionHandler)
	http.HandleFunc("/api/unregistered-save-game-data", unregisteredSaveGameDataHandler)
	http.HandleFunc("/api/registered-save-game-data", registeredSaveGameDataHandler)
	http.HandleFunc("/api/player-login", loginHandler)
	http.HandleFunc("/api/player-logout", logoutHandler)
	http.HandleFunc("/api/fetch-registered-game-data", fetchGameDataHandler)
	http.HandleFunc("/api/receive-heartbeat", heartBeatHandler)
	fmt.Println("Server is running on http://localhost:6673")
	log.Fatal(http.ListenAndServe(":6673", nil))
}
