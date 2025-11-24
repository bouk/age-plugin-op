package main

import (
	"fmt"
	"log"
	"os"

	"filippo.io/age/plugin"
)

func main() {
	if len(os.Args) == 1 {
		identity := plugin.EncodeIdentity("op", nil)
		fmt.Println(identity)
		return
	}

	p, err := plugin.New("op")
	if err != nil {
		log.Fatal(err)
	}
	p.HandleIdentity(NewIdentity)

	os.Exit(p.Main())
}
