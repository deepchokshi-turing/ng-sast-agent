package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"example.com/app/internal/app"
)

func main() {
	request := strings.Join(os.Args[1:], " ")
	if request == "" {
		request = "hello"
	}
	out, _ := json.MarshalIndent(app.Handle(request), "", "  ")
	fmt.Println(string(out))
}
