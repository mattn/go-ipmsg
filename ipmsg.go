package ipmsg

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/text/encoding/japanese"
)

const (
	ProtocolVersion = 1
)

const (
	IpMsgBrEntry    = 0x00000001
	IpMsgBrExit     = 0x00000002
	IpMsgAnsEntry   = 0x00000003
	IpMsgBrAbsence  = 0x00000004
	IpMsgSendMsg    = 0x00000020
	IpMsgRecvMsg    = 0x00000021
	IpMsgReadMsg    = 0x00000030
	IpMsgDelMsg     = 0x00000031
	IpMsgAnsReadMsg = 0x00000032
	IpMsgGetInfo    = 0x00000040
	IpMsgSendInfo   = 0x00000041

	IpMsgSendCheckOpt = 0x00000100
	IpMsgSecRetOpt    = 0x00000200
	IpMsgBroadcastOpt = 0x00000400
	IpMsgMulticastOpt = 0x00000800
	IpMsgNoPopupOpt   = 0x00001000
	IpMsgAutoRetOpt   = 0x00002000
	IpMsgRetryOpt     = 0x00004000
	IpMsgPasswordOpt  = 0x00008000
	IpMsgNoLogOpt     = 0x00020000
	IpMsgNewMultiOpt  = 0x00040000
	IpMsgNoAddListOpt = 0x00080000
	IpMsgReadCheckOpt = 0x00100000

	IpMsgAbsenceOpt    = 0x00000100
	IpMsgServerOpt     = 0x00000200
	IpMsgDialUpOpt     = 0x00010000
	IpMsgFileAttachOpt = 0x00200000
	IpMsgEncryptOpt    = 0x00400000
	IpMsgUtf8Opt       = 0x00800000
	IpMsgCanUtf8Opt    = 0x01000000
	IpMsgEncExtMsgOpt  = 0x04000000
	IpMsgClipboardOpt  = 0x08000000
	IpMsgCanFileEncOpt = 0x00001000

	IpMsgGetFileData  = 0x00000060
	IpMsgReleaseFiles = 0x00000061
	IpMsgGetDirFiles  = 0x00000062

	IpMsgFileRegular   = 0x00000001
	IpMsgFileDir       = 0x00000002
	IpMsgFileRetParent = 0x00000003 // return parent directory
	IpMsgFileSymlink   = 0x00000004
	IpMsgFileClipboard = 0x00000020 // for Windows Clipboard

	IpMsgFileUID          = 0x00000001
	IpMsgFileUserName     = 0x00000002 // uid by string
	IpMsgFileGID          = 0x00000003
	IpMsgFileGroupName    = 0x00000004 // gid by string
	IpMsgFilePerm         = 0x00000010 // for UNIX
	IpMsgFileMajorNo      = 0x00000011 // for UNIX devfile
	IpMsgFileMinorNo      = 0x00000012 // for UNIX devfile
	IpMsgFileCTime        = 0x00000013 // for UNIX
	IpMsgFileMTime        = 0x00000014
	IpMsgFileATime        = 0x00000015
	IpMsgFileCreateTime   = 0x00000016
	IpMsgFileCreator      = 0x00000020 // for Mac
	IpMsgFileFileType     = 0x00000021 // for Mac
	IpMsgFileFinderInfo   = 0x00000022 // for Mac
	IpMsgFileACL          = 0x00000030
	IpMsgFileAliasFname   = 0x00000040 // alias fname
	IpMsgFileUnicodeFname = 0x00000041 // UNICODE fname
)

type Host struct {
	Nickname string
	Group    string
	UTF8     bool
	host     *net.UDPAddr
}

type Attachment struct {
	ID        int64
	PacketID  int64
	Name      string
	Size      int64
	Time      time.Time
	Type      int64
	Attr      map[int64]string
	Clipboard bool
	from      *net.UDPAddr
}

type Msg struct {
	packetID    int64
	username    string
	hostname    string
	body        string
	conn        *Conn
	from        *net.UDPAddr
	readCheck   bool
	opened      bool
	attachments []*Attachment
}

func (msg *Msg) Username() string {
	return msg.username
}

func (msg *Msg) Hostname() string {
	return msg.hostname
}

func (msg *Msg) From() string {
	return msg.from.String()
}

func (msg *Msg) Delete() {
	if !msg.opened && msg.readCheck {
		msg.conn.sendudp(msg.from, IpMsgDelMsg, fmt.Sprint(msg.packetID))
	}
	msg.body = ""
}

func (msg *Msg) Body() string {
	if msg.readCheck {
		msg.conn.sendudp(msg.from, IpMsgReadMsg, fmt.Sprint(msg.packetID))
	}
	msg.opened = true
	return msg.body
}

func (msg *Msg) Attachments() []*Attachment {
	return msg.attachments
}

type Conn struct {
	username  string
	hostname  string
	quit      chan struct{}
	conn      *net.UDPConn
	broadcast *net.UDPAddr
	hosts     map[string]*Host
	recvCb    func(*Msg) error
	seq       int64
	Debug     bool
}

func (c *Conn) packetID() int64 {
	return atomic.AddInt64(&c.seq, 1)
}

func (c *Conn) sendudp(to *net.UDPAddr, cmd int, msg string) error {
	_, err := c.conn.WriteToUDP([]byte(fmt.Sprintf("%d:%d:%s:%s:%d:%s", ProtocolVersion, c.packetID(), c.username, c.hostname, cmd, msg)), to)
	return err
}

func parseAttr(s string) map[int64]string {
	attrs := make(map[int64]string)
	for _, attr := range strings.Split(s, ",") {
		if tok := strings.SplitN(attr, "=", 2); len(tok) == 2 {
			kind, _ := strconv.ParseInt(tok[0], 16, 64)
			attrs[kind] = tok[1]
		}
	}
	return attrs
}

func (c *Conn) download(conn net.Conn, base string, attachment *Attachment) error {
	switch attachment.Type {
	case IpMsgFileDir:
		_, err := conn.Write([]byte(fmt.Sprintf("%d:%d:%s:%s:%d:%x:%x", ProtocolVersion, c.packetID(), c.username, c.hostname, IpMsgGetDirFiles, attachment.PacketID, attachment.ID)))
		if err != nil {
			return err
		}
		buf := bufio.NewReader(conn)
		p := base
	loop:
		for {
			b, err := buf.ReadBytes(':')
			if err != nil {
				return err
			}
			headerSize, _ := strconv.ParseInt(string(b[:len(b)-1]), 16, 64)
			fi := make([]byte, headerSize-int64(len(b)))
			n, err := buf.Read(fi)
			if err != nil {
				return err
			}

			ftoken := bytes.Split(fi[:n], []byte{':'})
			if len(ftoken) > 2 {
				fname := filepath.Base(string(ftoken[0]))
				h, ok := c.hosts[attachment.from.String()]
				if ok && h.UTF8 {
					fname, _ = japanese.ShiftJIS.NewDecoder().String(string(ftoken[0]))
				}
				fsize, _ := strconv.ParseInt(string(ftoken[1]), 16, 64)
				ftype, _ := strconv.ParseInt(string(ftoken[2]), 16, 64)
				fattr := parseAttr(string(ftoken[3]))
				switch ftype {
				case IpMsgFileDir:
					if fname == "." || fname == ".." {
						return errors.New("invalid attachment")
					}
					fname = filepath.Join(p, fname)
					err := os.MkdirAll(fname, 0755)
					if err != nil {
						return err
					}

					mtime := time.Now()
					if t, ok := fattr[IpMsgFileMTime]; ok {
						if tt, err := strconv.ParseInt(t, 16, 64); err == nil {
							mtime = time.Unix(tt, 0)
						}
					}
					err = os.Chtimes(p, mtime, mtime)
					if err != nil {
						return err
					}
				case IpMsgFileRegular:
					if fname == "." || fname == ".." {
						return errors.New("invalid attachment")
					}
					fname = filepath.Join(p, fname)
					f, err := os.Create(fname)
					if err != nil {
						return err
					}
					io.CopyN(f, buf, fsize)
					f.Close()

					mtime := time.Now()
					if t, ok := fattr[IpMsgFileMTime]; ok {
						if tt, err := strconv.ParseInt(t, 16, 64); err == nil {
							mtime = time.Unix(tt, 0)
						}
					}
					err = os.Chtimes(fname, mtime, mtime)
					if err != nil {
						return err
					}
				case IpMsgFileRetParent:
					p = filepath.Dir(p)
					if len(p) <= len(base) {
						break loop
					}
				}
			}
		}
	case IpMsgFileRegular, IpMsgFileClipboard:
		fname := filepath.Base(attachment.Name)
		f, err := os.Create(fname)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = conn.Write([]byte(fmt.Sprintf("%d:%d:%s:%s:%d:%x:%x:0", ProtocolVersion, c.packetID(), c.username, c.hostname, IpMsgGetFileData, attachment.PacketID, attachment.ID)))
		if err != nil {
			return err
		}
		var b [1024]byte
		for {
			n, err := conn.Read(b[:])
			if err != nil {
				return err
			}
			f.Write(b[:n])
		}
		mtime := time.Now()
		if t, ok := attachment.Attr[IpMsgFileMTime]; ok {
			if tt, err := strconv.ParseInt(t, 16, 64); err == nil {
				mtime = time.Unix(tt, 0)
			}
		}
		err = os.Chtimes(fname, mtime, mtime)
		if err != nil {
			return err
		}
	}
	c.sendudp(attachment.from, IpMsgReleaseFiles, fmt.Sprintf("%d:%d", attachment.PacketID, attachment.ID))
	return nil
}

func (c *Conn) Download(dir string, attachment *Attachment) error {
	if attachment == nil {
		return nil
	}
	conn, err := net.Dial("tcp", attachment.from.String())
	if err != nil {
		return err
	}
	defer conn.Close()

	return c.download(conn, dir, attachment)
}

func (c *Conn) SendMsg(to string, msg string) error {
	msg = strings.Replace(msg, ":", "::", -1)

	utf8 := false
	for k, v := range c.hosts {
		if k == to {
			utf8 = v.UTF8
			break
		}
	}
	if !utf8 {
		msg, _ = japanese.ShiftJIS.NewEncoder().String(msg)
	}
	addr, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		return err
	}
	return c.sendudp(addr, IpMsgSendMsg, msg)
}

func (c *Conn) Closed() bool {
	return c.quit == nil
}

func (c *Conn) Close() error {
	c.sendudp(c.broadcast, IpMsgBrExit, "")
	c.quit = nil
	return c.conn.Close()
}

func (c *Conn) Wait() {
	<-c.quit
}

func (c *Conn) recvudp() ([]byte, *net.UDPAddr, error) {
	var b [1024]byte
	n, from, err := c.conn.ReadFromUDP(b[:])
	if err != nil {
		return nil, nil, err
	}
	return b[:n], from, err
}

func Dial(username string) (*Conn, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	dst, err := net.ResolveUDPAddr("udp", ":2425")
	if err != nil {
		return nil, err
	}
	lis, err := net.ListenUDP("udp", dst)
	if err != nil {
		return nil, err
	}
	conn := &Conn{
		username: username,
		hostname: hostname,
		quit:     make(chan struct{}),
		conn:     lis,
		broadcast: &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: 2425,
		},
		seq:   time.Now().Unix(),
		hosts: make(map[string]*Host),
	}

	go conn.doServe()

	return conn, nil
}

func (c *Conn) doServe() {
	c.sendudp(c.broadcast, 0|
		IpMsgBrEntry|
		IpMsgUtf8Opt|
		//IpMsgClipboardOpt|
		0,
		c.username)

	defer func() {
		c.conn.Close()
		c.quit <- struct{}{}
	}()

	for {
		b, from, err := c.recvudp()
		if err != nil {
			break
		}
		telegram := bytes.SplitN(b, []byte{':'}, 6)
		if len(telegram) < 5 {
			continue
		}
		cmd, err := strconv.Atoi(string(telegram[4]))
		if err != nil {
			continue
		}
		if c.Debug {
			log.Printf("CMD=%x\n%s\n", cmd, hex.Dump(b))
		}
		h, ok := c.hosts[from.String()]
		if !ok {
			h = &Host{host: from}
			c.hosts[from.String()] = h

		}

		switch cmd & 0xff {
		case IpMsgBrEntry:
			if cmd&IpMsgUtf8Opt != 0 {
				h.UTF8 = true
			}
			c.sendudp(from, IpMsgAnsEntry, c.username)
			fallthrough
		case IpMsgAnsEntry:
			dim := bytes.Split(telegram[5], []byte{0})
			var nickname, group string
			if len(dim) == 2 {
				nickname, group = string(dim[0]), string(dim[1])
			} else {
				nickname = string(dim[0])
			}
			h.Nickname = nickname
			h.Group = group
		case IpMsgBrExit:
			delete(c.hosts, from.String())
		case IpMsgGetInfo:
			c.sendudp(from, IpMsgSendInfo, "go-ipmsg v0.0.1")
		case IpMsgSendMsg:
			dim := bytes.Split(telegram[5], []byte{0})
			if cmd&IpMsgUtf8Opt == 0 {
				dim[0], _ = japanese.ShiftJIS.NewDecoder().Bytes(dim[0])
			}
			if len(dim) < 2 {
				continue
			}
			var msg Msg
			if len(h.Nickname) > 0 {
				msg.username = h.Nickname
			} else {
				msg.username = string(telegram[2])
			}
			msg.hostname = from.String()
			msg.body = string(dim[0])
			msg.from = from
			msg.conn = c
			msg.readCheck = cmd&IpMsgSecRetOpt != 0

			if cmd&IpMsgFileAttachOpt != 0 || cmd&IpMsgClipboardOpt != 0 {
				for _, fi := range bytes.Split(dim[1], []byte{'\a'}) {
					ftoken := bytes.SplitN(fi, []byte{':'}, 6)
					if len(ftoken) == 6 {
						fid, _ := strconv.ParseInt(string(ftoken[0]), 10, 64)
						fname := string(ftoken[1])
						if cmd&IpMsgUtf8Opt == 0 {
							fname, _ = japanese.ShiftJIS.NewDecoder().String(string(ftoken[1]))
						}
						fpacketID, _ := strconv.ParseInt(string(telegram[1]), 10, 64)
						fsize, _ := strconv.ParseInt(string(ftoken[2]), 16, 64)
						ftime, _ := strconv.ParseInt(string(ftoken[3]), 16, 64)
						ftype, _ := strconv.ParseInt(string(ftoken[4]), 16, 64)
						msg.attachments = append(msg.attachments, &Attachment{
							ID:        fid,
							PacketID:  fpacketID,
							Name:      fname,
							Size:      fsize,
							Time:      time.Unix(ftime, 0),
							Type:      ftype,
							Attr:      parseAttr(string(ftoken[5])),
							Clipboard: cmd&IpMsgClipboardOpt != 0,
							from:      from,
						})
					}
				}
			}
			c.sendudp(from, IpMsgRecvMsg, string(telegram[1]))
			if c.recvCb != nil {
				go c.recvCb(&msg)
			}
		default:
		}
	}
}

func (c *Conn) Hosts() map[string]*Host {
	return c.hosts
}

func (c *Conn) Recv(f func(*Msg) error) {
	c.recvCb = f
}
