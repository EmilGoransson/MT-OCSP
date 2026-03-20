package main

import (
	mt "github.com/txaty/go-merkletree"
)

var defaultMerkleConfig = &mt.Config{
	DisableLeafHashing: true,
	SortSiblingPairs:   true,
	Mode:               mt.ModeTreeBuild,
}

func main() {

}
