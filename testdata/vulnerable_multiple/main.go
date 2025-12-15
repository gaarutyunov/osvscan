package main

import (
	"fmt"
	_ "github.com/gogo/protobuf/proto"
	_ "golang.org/x/image/tiff"
)

func main() {
	fmt.Println("Using multiple vulnerable packages")
}
