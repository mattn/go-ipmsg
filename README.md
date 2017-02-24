# go-ipmsg

IP Messenger Client for golang

## Usage

```go
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
```

## Installation

```
$ go get github.com/mattn/go-ipmsg
```

## License

MIT

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
