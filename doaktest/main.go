package main

import (
	"fmt"
	"html"
	"io"
	"log"
	"time"

	"github.com/johnsiilver/http"
)

func main() {
	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	log.Println("before")
	go http.ListenAndServe(":8080", nil)
	log.Println("after")
	time.Sleep(1 * time.Second)
	log.Println("after sleep")

	resp, err := http.Get("http://localhost:8080/bar")
	if err != nil {
		panic(err)
	}

	b, _ := io.ReadAll(resp.Body)
	log.Println(string(b))
}
