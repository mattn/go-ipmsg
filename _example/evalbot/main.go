package main

import (
	"go/token"
	"go/types"
	"log"
	"strings"

	"github.com/mattn/go-ipmsg"
)

func main() {
	conn, err := ipmsg.Dial("evalbot")
	if err != nil {
		log.Fatal(err)
	}
	conn.Debug = true
	conn.Recv(func(msg *ipmsg.Msg) error {
		body := ""
		for _, line := range strings.Split(msg.Body(), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, ">") {
				body = line
				break
			}
		}

		val, err := types.Eval(token.NewFileSet(), types.NewPackage("main", "main"), token.NoPos, body)
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
