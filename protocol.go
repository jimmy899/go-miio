package miio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

/*
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Magic number = 0x2131         | Packet Length (incl. header)  |
|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
| Unknown1                                                      |
|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
| Device ID ("did")                                             |
|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
| Stamp                                                         |
|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
| MD5 checksum                                                  |
| ... or Device Token in response to the "Hello" packet         |
|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
| optional variable-sized data (encrypted)                      |
|...............................................................|

reference to https://github.com/OpenMiHome/mihome-binary-protocol/blob/master/doc/PROTOCOL.md

*/

const ffffffff uint32 = 0xffffffff

func (result *MiioResult) UnmarshalJSON(input []byte) error {
	// fmt.Printf("%v\n", string(input))
	var err error

	reader := bytes.NewReader(input)
	decoder := json.NewDecoder(reader)
	err = decoder.Decode(&result.InMap)

	if err != nil {
		fake := fmt.Sprintf(`{"array":%s}`, string(input))
		reader = bytes.NewReader([]byte(fake))
		decoder := json.NewDecoder(reader)
		err = decoder.Decode(&result.InArray)
		if err != nil {
			fmt.Printf("%v\n", fake)
			return err
		}
		// fmt.Printf("decode as array\n")
	} else {
		// fmt.Printf("decode as map\n")
	}

	return nil
}

func (result *MiioResult) MarshalJSON() ([]byte, error) {
	// fmt.Printf("%v\n", string(input))
	return nil, nil
}

func MiioDeviceNew(ip string, token string) (*MiioDevice, error) {
	device := &MiioDevice{}
	var err error
	device.token, err = hex.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("error while decode `%x`", token)
	}

	if len(device.token) != 16 {
		return nil, fmt.Errorf("invalid token")
	}
	device.ip = net.ParseIP(ip)
	if device.ip == nil {
		return nil, fmt.Errorf("invalid ip address `%s`", ip)
	}

	keygen := md5.New()
	keygen.Write(device.token)
	device.key = keygen.Sum(nil)
	ivgen := md5.New()
	ivgen.Write(device.key)
	ivgen.Write(device.token)
	device.iv = ivgen.Sum(nil)

	device.deviceid = ffffffff
	device.stamp = ffffffff

	// fmt.Printf("dev{key:%s,iv:%s}\n", hex.EncodeToString(device.key), hex.EncodeToString(device.iv))

	device.conn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: device.ip, Port: 54321})
	if err != nil {
		return nil, err
	}

	return device, nil
}

func (device *MiioDevice) Handshake() error {

	var pkt *MiioPacket
	var raw []byte
	var resp interface{}
	retries := 3

	pkt = MiioPacketNew(``)
	raw, err := pkt.MiioPacketToWire(device)
	if err != nil {
		fmt.Printf("%v\n", err)
		return err
	}
	// fmt.Printf("raw: %s %s %s\n", hex.EncodeToString(raw[:16]), hex.EncodeToString(raw[16:32]), hex.EncodeToString(raw[32:]))

	readch := make(chan interface{})
	for retries > 0 && resp == nil {
		_, err = device.conn.Write(raw)
		if err != nil {
			return err
		}

		timeout := time.NewTicker(2 * time.Second)

		go func() {
			response := make([]byte, 8192)
			rl, err := device.conn.Read(response)
			if err != nil {
				readch <- err
			}

			// fmt.Printf("<- (%d) %x %x %x\n", rl, response[:16], response[16:32], response[32:rl])

			packet, err := device.MarshalPacket(response[:rl])
			if err != nil {
				readch <- err
			}

			readch <- packet
		}()

		select {
		case <-timeout.C:
			retries--
		case resp = <-readch:
		}

		timeout.Stop()

		if resp == nil {
			fmt.Printf("handshake: try again ... \n")
		}
	}

	if resp == nil {
		return fmt.Errorf("handshake timeout")
	}

	packet, ok := resp.(*MiioPacket)
	if !ok {
		err, ok := resp.(error)
		if !ok {
			return fmt.Errorf("PANIC: invalid type")
		}
		return err
	}

	device.deviceid = packet.deviceid
	device.stamp = packet.stamp
	device.msgid = 0
	device.baseTimestamp = time.Now()

	// fmt.Printf("device (%v) is handshaked\n", device)

	return nil
}

func (device *MiioDevice) readWithTimeout() (*MiioResponse, error) {
	recvbuf := make([]byte, 8192)
	var response MiioResponse
	var retResponse *MiioResponse
	var err error

	readch := make(chan interface{})
	go func() {
		rl, err := device.conn.Read(recvbuf)
		// fmt.Printf("<- (%d) %x %x %x\n", rl, recvbuf[:16], recvbuf[16:32], recvbuf[32:rl])
		pkt, err := device.MarshalPacket(recvbuf[:rl])

		if err != nil {
			readch <- err
		} else {
			// response = MiioResponse.
			// fmt.Printf("payload in response: %v\n", string(pkt.payload))

			err = json.Unmarshal([]byte(pkt.payload), &response)
			if err != nil {
				readch <- err
			} else {
				readch <- &response
			}
		}
	}()

	ticker := time.NewTicker(3 * time.Second)
	select {
	case <-ticker.C:
		// timeout
		retResponse = nil
		err = fmt.Errorf("read timed out")
	case msg := <-readch:
		switch msg.(type) {
		case *MiioResponse:
			retResponse = msg.(*MiioResponse)
			err = nil
		case error:
			retResponse = nil
			err = msg.(error)
		}
	}

	ticker.Stop()
	return retResponse, err
}

func (device *MiioDevice) Send(request *MiioCommand) (*MiioResponse, error) {

	request.ID = atomic.AddUint32(&device.msgid, 1)

	js, err := json.Marshal(&request)
	if err != nil {
		return nil, err
	}

	pkt := MiioPacketNew(string(js))

	raw, err := pkt.MiioPacketToWire(device)

	// fmt.Printf("payload: %v\n", pkt.payload)
	// fmt.Printf("-> (%d) %x %x %x\n", len(raw), raw[:16], raw[16:32], raw[32:])
	_, err = device.conn.Write(raw)
	if err != nil {
		return nil, err
	}

	return device.readWithTimeout()
}

func MiioPacketNew(payload string) *MiioPacket {
	return &MiioPacket{
		len:      uint16(len(payload)) + 32,
		payload:  []byte(payload),
		deviceid: 0,
		stamp:    0,
	}
}

func (device *MiioDevice) MarshalPacket(data []byte) (*MiioPacket, error) {

	var packet MiioPacket
	var magic uint16
	var err error
	var csum = make([]byte, 16)
	reader := bytes.NewReader(data)

	err = binary.Read(reader, binary.BigEndian, &magic)
	if err != nil {
		return nil, err
	}
	if magic != 0x2131 {
		return nil, fmt.Errorf("invalid packet magic")
	}

	err = binary.Read(reader, binary.BigEndian, &packet.len)
	if err != nil {
		return nil, err
	}
	if packet.len < 32 {
		return nil, fmt.Errorf(" packet is too small")
	}
	if packet.len%16 > 0 {

		return nil, fmt.Errorf("invalid packet length")
	}
	if packet.len != uint16(len(data)) {
		// FIXME: this might a response for a corrupted packet
		return nil, fmt.Errorf("invalid packet length")
	}

	var unknown uint32

	err = binary.Read(reader, binary.BigEndian, &unknown)
	if err != nil {
		return nil, err
	}
	if unknown != 0 {
		return nil, fmt.Errorf("invalid unknown")
	}

	err = binary.Read(reader, binary.BigEndian, &packet.deviceid)
	if err != nil {
		return nil, err
	}
	if device.isHandshaked() && packet.deviceid != device.deviceid {
		return nil, fmt.Errorf("this is not my packet (%x, and expected %x)", packet.deviceid, device.deviceid)
	}

	err = binary.Read(reader, binary.BigEndian, &packet.stamp)
	if err != nil {
		return nil, err
	}

	rl, err := reader.Read(csum)
	if err != nil {
		return nil, err
	}
	if rl != len(csum) {
		return nil, fmt.Errorf("packet is too short")
	}

	if packet.len > 32 {
		encrypted := make([]byte, packet.len-32)

		rl, err := reader.Read(encrypted)
		if err != nil {
			return nil, err
		}
		if rl != len(encrypted) {
			return nil, fmt.Errorf("packet is too short")
		}

		verifier := md5.New()
		verifier.Write(data[0:16])
		verifier.Write(device.token)
		verifier.Write(data[32:])

		vsum := verifier.Sum(nil)

		if bytes.Compare(csum, vsum) != 0 {
			return nil, fmt.Errorf("checksum is mismatch")
		}

		block, err := aes.NewCipher(device.key)
		if err != nil {
			return nil, err
		}
		bmode := cipher.NewCBCDecrypter(block, device.iv)
		bmode.CryptBlocks(encrypted, encrypted)
		bytePadding := int(encrypted[len(encrypted)-1])
		if bytePadding > 16 || bytePadding > len(encrypted) {
			err = fmt.Errorf("invalid padding character")
		} else {
			packet.payload = make([]byte, len(encrypted)-bytePadding)
			copy(packet.payload, encrypted[:len(encrypted)-bytePadding])
		}
	}

	return &packet, nil
}

func (packet *MiioPacket) encryptPayload(key, iv []byte) []byte {

	data := []byte(packet.payload)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	bm := cipher.NewCBCEncrypter(block, iv)
	padding := 16 - (len(data) % len(key))

	paddingChunk := make([]byte, padding)
	for i := 0; i < len(paddingChunk); i++ {
		paddingChunk[i] = byte(padding)
	}
	data = append(data, paddingChunk...)
	// fmt.Printf("size: %d\n", len(data))
	// fmt.Printf("data: %v\n", hex.EncodeToString(data))
	bm.CryptBlocks(data, data)
	// fmt.Printf("encrypted: %v\n", hex.EncodeToString(data))
	return data
}

func (device *MiioDevice) isHandshaked() bool {
	return device.deviceid != ffffffff
}

func (packet *MiioPacket) MiioPacketToWire(device *MiioDevice) ([]byte, error) {
	var output []byte

	sum := md5.New()
	buf := new(bytes.Buffer)

	// magic
	binary.Write(buf, binary.BigEndian, uint16(0x2131))
	pktlen := len(device.key) * ((int(packet.len) + len(device.key) - 1) / len(device.key))
	// packet length
	binary.Write(buf, binary.BigEndian, uint16(pktlen))

	// unknown
	if device.isHandshaked() {
		binary.Write(buf, binary.BigEndian, uint32(0))
	} else {
		binary.Write(buf, binary.BigEndian, uint32(ffffffff))
	}

	// device id
	binary.Write(buf, binary.BigEndian, uint32(device.deviceid))

	// stamp
	timeDiff := time.Now().UnixNano() - device.baseTimestamp.UnixNano()
	if device.isHandshaked() {
		binary.Write(buf, binary.BigEndian, uint32(int64(device.stamp)+timeDiff/1000000000))
	} else {
		binary.Write(buf, binary.BigEndian, uint32(ffffffff))
	}

	if device.isHandshaked() {
		encrypted := packet.encryptPayload(device.key, device.iv)
		// md5sum
		sum.Write(buf.Bytes())
		sum.Write(device.token)
		sum.Write(encrypted)

		buf.Write(sum.Sum(nil))

		// encrypted payload
		buf.Write(encrypted)
	} else {
		binary.Write(buf, binary.BigEndian, uint32(ffffffff))
		binary.Write(buf, binary.BigEndian, uint32(ffffffff))
		binary.Write(buf, binary.BigEndian, uint32(ffffffff))
		binary.Write(buf, binary.BigEndian, uint32(ffffffff))
	}
	output = buf.Bytes()

	// fmt.Printf("-> (%d) %x %x %x\n", len(output), output[:16], output[16:32], output[32:])
	return output, nil
}
