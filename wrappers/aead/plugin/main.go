package main

import (
	"fmt"
	"os"

	aead "github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
)

func main() {
	if err := aead.ServePlugin(); err != nil {
		fmt.Print("Error serving plugin: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}
