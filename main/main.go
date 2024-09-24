package main

import (
	"Backend/impl"
	_ "github.com/lib/pq"
)

func main() {
	impl.StartHttpServer()
}
