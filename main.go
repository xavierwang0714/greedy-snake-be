package main

import (
	"snake/impl"

	_ "github.com/lib/pq"
)

func main() {
	impl.StartHttpServer()
}
