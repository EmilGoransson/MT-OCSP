package main

import "fmt"

func main() {
	err := LogTest()
	if err != nil {
		panic(err)
	}
}
