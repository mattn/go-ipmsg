package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strings"

	"github.com/mattn/go-ipmsg"
)

func main() {
	curuser, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	conn, err := ipmsg.Dial(curuser.Username)
	if err != nil {
		log.Fatal(err)
	}
	conn.Recv(func(msg *ipmsg.Msg) error {
		fmt.Printf("From: %s on %s\n", msg.Username(), msg.Hostname())
		fmt.Println()
		fmt.Println(msg.Body())
		for _, attachment := range msg.Attachments() {
			fmt.Printf("Attachment: %s (%d)\n", attachment.Name, attachment.Size)
			conn.Download(attachment)
		}
		fmt.Println("---")
		return nil
	})
	conn.Debug = true

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)
	go func() {
		<-sc
		conn.Close()
	}()

	scan := bufio.NewScanner(os.Stdin)
	for !conn.Closed() {
		for k, v := range conn.Hosts() {
			fmt.Printf("%s: %s\n", k, v.Nickname)
		}
		if scan.Scan() {
			token := strings.SplitN(scan.Text(), " ", 2)
			if len(token) == 2 {
				conn.SendMsg(token[0], token[1])
			}
		}
		if scan.Err() != nil {
			break
		}
	}
}
