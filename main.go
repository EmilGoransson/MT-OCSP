package main

import "fmt"

func main() {

	sparseTree := NewSparseMerkle()

	fmt.Println(sparseTree)

	tree, _ := NewMerkle()

	fmt.Println(tree)

	combinedTree, _ := NewCombinedTree()

	fmt.Println(combinedTree)

}
