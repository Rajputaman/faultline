package main

import (
	"fmt"

	"github.com/faultline-go/faultline/testdata/simple-go-module/internal/store"
	"github.com/faultline-go/faultline/testdata/simple-go-module/pkg/mathy"
)

func main() {
	fmt.Println(mathy.Add(2, store.Value()))
}
