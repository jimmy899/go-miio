package miio

import "time"
import "net"

type MiioDevice struct {
	ip       net.IP
	token    []byte
	key      []byte
	iv       []byte
	deviceid uint32
	msgid    uint32
	stamp    uint32

	baseTimestamp time.Time
	conn          *net.UDPConn
	logLevel int
}

type MiioPacket struct {
	len      uint16
	payload  []byte
	deviceid uint32
	stamp    uint32
}

type MiioCommand struct {
	Method string   `json:"method"`
	Params []string `json:"params"`
	ID     uint32   `json:"id"`
}

type MiioResponse struct {
	Result MiioResult `json:"result"`
	ID     uint32     `json:"id"`
}

type MiioResult struct {
	InMap   map[string]interface{}
	InArray MiioArrayInResult
}

type MiioArrayInResult struct {
	Item []interface{} `json:"array"`
}
