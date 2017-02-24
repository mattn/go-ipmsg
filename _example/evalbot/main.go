package main

import (
	"go/token"
	"go/types"
	"log"

	"github.com/mattn/go-ipmsg"
)

func main() {
	conn, err := ipmsg.Dial("evalbot")
	if err != nil {
		log.Fatal(err)
	}
	conn.Debug = true
	conn.Recv(func(msg *ipmsg.Msg) error {
		val, err := types.Eval(token.NewFileSet(), types.NewPackage("main", "main"), token.NoPos, msg.Body())
		if err != nil {
			conn.SendMsg(msg.From(), err.Error())
		} else if val.Value != nil {
			conn.SendMsg(msg.From(), val.Value.String())
		} else {
			conn.SendMsg(msg.From(), "WTF!?")
		}
		return nil
	})
	conn.Wait()
}
