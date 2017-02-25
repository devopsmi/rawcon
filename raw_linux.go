package rawcon

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"os/exec"
	"strconv"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

type RAWConn struct {
	conn  *net.IPConn
	wconn *net.IPConn
	rconn *ipv4.RawConn
	udp   net.Conn
	layer *pktLayers
	buf   []byte
	clean *exec.Cmd
}

func (raw *RAWConn) Close() (err error) {
	if raw.clean != nil {
		raw.clean.Run()
	}
	if raw.udp != nil && raw.wconn != nil {
		raw.sendFin()
	}
	if raw.udp != nil {
		err = raw.udp.Close()
	}
	if raw.conn != nil {
		err1 := raw.conn.Close()
		if err1 != nil {
			err = err1
		}
	}
	if raw.wconn != nil {
		err2 := raw.wconn.Close()
		if err2 != nil {
			err = err2
		}
	}
	return
}

func (raw *RAWConn) updateTCP() {
	tcp := raw.layer.tcp
	tcp.flags = 0
	tcp.ecn = 0
	tcp.reserved = 0
	tcp.chksum = 0
	tcp.payload = nil
}

func (raw *RAWConn) sendPacket() (err error) {
	layer := raw.layer
	data := layer.tcp.marshal(layer.ip4.srcip, layer.ip4.dstip)
	_, err = raw.wconn.WriteTo(data, &net.IPAddr{IP: layer.ip4.dstip})
	return
}

func (raw *RAWConn) sendSyn() (err error) {
	raw.updateTCP()
	tcp := raw.layer.tcp
	tcp.setFlag(SYN)
	options := tcp.options
	defer func() { tcp.options = options }()
	tcp.options = append(tcp.options, TCPOption{
		kind:   TCPOptionKindMSS,
		length: 4,
		data:   []byte{0x5, 0xb4},
	})
	return raw.sendPacket()
}

func (conn *RAWConn) sendSynAck() (err error) {
	conn.updateTCP()
	tcp := conn.layer.tcp
	tcp.setFlag(SYN | ACK)
	options := tcp.options
	defer func() { tcp.options = options }()
	tcp.options = append(tcp.options, TCPOption{
		kind:   TCPOptionKindMSS,
		length: 4,
		data:   []byte{0x5, 0xb4},
	})
	return conn.sendPacket()
}

func (conn *RAWConn) sendAck() (err error) {
	conn.updateTCP()
	conn.layer.tcp.setFlag(ACK)
	return conn.sendPacket()
}

func (conn *RAWConn) sendFin() (err error) {
	conn.updateTCP()
	conn.layer.tcp.setFlag(FIN)
	return conn.sendPacket()
}

func (conn *RAWConn) sendRst() (err error) {
	conn.updateTCP()
	conn.layer.tcp.setFlag(RST)
	return conn.sendPacket()
}

func (raw *RAWConn) Write(b []byte) (n int, err error) {
	n = len(b)
	raw.updateTCP()
	tcp := raw.layer.tcp
	tcp.setFlag(PSH | ACK)
	tcp.payload = b
	err = raw.sendPacket()
	tcp.seqn += uint32(n)
	return
}

func (raw *RAWConn) ReadTCPLayer() (tcp *TCPLayer, addr *net.UDPAddr, err error) {
	for {
		var n int
		var ipaddr *net.IPAddr
		n, ipaddr, err = raw.conn.ReadFromIP(raw.buf)
		if err != nil {
			e, ok := err.(net.Error)
			if ok && e.Temporary() {
				raw.SetReadDeadline(time.Time{})
			}
			return
		}
		tcp, err = decodeTCPlayer(raw.buf[:n])
		if err != nil {
			return
		}
		if tcp.chkFlag(RST) {
			if ignrst {
				continue
			} else {
				err = fmt.Errorf("connect reset by peer %s", addr.String())
			}
		}
		addr = &net.UDPAddr{
			IP:   ipaddr.IP,
			Port: tcp.srcPort,
		}
		return
	}
}

func (raw *RAWConn) Read(b []byte) (n int, err error) {
	n, _, err = raw.ReadFrom(b)
	return
}

func (conn *RAWConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.srcip,
		Port: conn.layer.tcp.srcPort,
	}
}

func (conn *RAWConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.dstip,
		Port: conn.layer.tcp.dstPort,
	}
}

func (raw *RAWConn) SetDeadline(t time.Time) error {
	return raw.conn.SetDeadline(t)
}

func (raw *RAWConn) SetReadDeadline(t time.Time) error {
	return raw.conn.SetReadDeadline(t)
}

func (raw *RAWConn) SetWriteDeadline(t time.Time) error {
	return raw.conn.SetWriteDeadline(t)
}

func (raw *RAWConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		var tcp *TCPLayer
		tcp, addr, err = raw.ReadTCPLayer()
		if err != nil {
			return
		}
		if tcp == nil || addr == nil {
			continue
		}
		if tcp.chkFlag(FIN) {
			err = fmt.Errorf("receive fin from %s", addr.String())
			return
		}
		if tcp.chkFlag(SYN | ACK) {
			err = raw.sendAck()
			if err != nil {
				return
			} else {
				continue
			}
		}
		n = len(tcp.payload)
		if n == 0 {
			continue
		}
		if uint64(tcp.seqn)+uint64(n) > uint64(raw.layer.tcp.ackn) {
			raw.layer.tcp.ackn = tcp.seqn + uint32(n)
		}
		copy(b, tcp.payload)
		return n, addr, err
	}
}

func (raw *RAWConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return raw.Write(b)
}

func DialRAW(address string) (raw *RAWConn, err error) {
	udp, err := net.Dial("udp4", address)
	if err != nil {
		return
	}
	ulocaladdr := udp.LocalAddr().(*net.UDPAddr)
	uremoteaddr := udp.RemoteAddr().(*net.UDPAddr)
	conn, err := net.DialIP("ip4:tcp", &net.IPAddr{IP: ulocaladdr.IP}, &net.IPAddr{IP: uremoteaddr.IP})
	fatalErr(err)
	wconn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: ulocaladdr.IP})
	fatalErr(err)
	if dscp != 0 {
		ipv4.NewConn(wconn).SetTOS(dscp)
	}
	rconn, err := ipv4.NewRawConn(conn)
	fatalErr(err)
	// https://www.kernel.org/doc/Documentation/networking/filter.txt
	rconn.SetBPF([]bpf.RawInstruction{
		{0x30, 0, 0, 0x00000009},
		{0x15, 0, 6, 0x00000006},
		{0x28, 0, 0, 0x00000006},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x00000000},
		{0x48, 0, 0, 0x00000002},
		{0x15, 0, 1, uint32(ulocaladdr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	})
	raw = &RAWConn{
		conn:  conn,
		wconn: wconn,
		rconn: rconn,
		udp:   udp,
		buf:   make([]byte, 65536),
		layer: &pktLayers{
			ip4: &IPv4Layer{
				srcip: ulocaladdr.IP,
				dstip: uremoteaddr.IP,
			},
			tcp: &TCPLayer{
				srcPort: ulocaladdr.Port,
				dstPort: uremoteaddr.Port,
				window:  12580,
				ackn:    0,
				data:    make([]byte, 65536),
			},
		},
	}
	binary.Read(rand.Reader, binary.LittleEndian, &(raw.layer.tcp.seqn))
	defer func() {
		if err != nil {
			raw.Close()
		} else {
			raw.SetReadDeadline(time.Time{})
		}
	}()
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
		"--sport", strconv.Itoa(ulocaladdr.Port), "-d", conn.RemoteAddr().String(),
		"--dport", strconv.Itoa(uremoteaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	raw.clean = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
		"--sport", strconv.Itoa(ulocaladdr.Port), "-d", conn.RemoteAddr().String(),
		"--dport", strconv.Itoa(uremoteaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	defer func() {
		if err != nil {
			raw.clean.Run()
			raw.clean = nil
			return
		}
	}()
	retry := 0
	layer := raw.layer
	var ackn uint32
	var seqn uint32
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		err = raw.sendSyn()
		if err != nil {
			return
		}
		err = raw.SetReadDeadline(time.Now().Add(time.Second * 1))
		if err != nil {
			return
		}
		var tcp *TCPLayer
		tcp, _, err = raw.ReadTCPLayer()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				continue
			}
		}
		if tcp.chkFlag(SYN | ACK) {
			layer.tcp.ackn = tcp.seqn + 1
			layer.tcp.seqn++
			ackn = layer.tcp.ackn
			seqn = layer.tcp.seqn
			err = raw.sendAck()
			if err != nil {
				return
			}
			break
		}
	}
	if noHTTP {
		return
	}
	retry = 0
	opt := getTCPOptions()
	var headers string
	if len(httpHost) != 0 {
		headers += "Host: " + httpHost + "\r\n"
		headers += "X-Online-Host: " + httpHost + "\r\n"
	}
	req := buildHTTPRequest(headers)
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		layer.tcp.options = opt
		layer.tcp.seqn = seqn
		_, err = raw.Write([]byte(req))
		if err != nil {
			return
		}
		layer.tcp.options = nil
		err = raw.SetReadDeadline(time.Now().Add(time.Second * 1))
		if err != nil {
			return
		}
		var tcp *TCPLayer
		tcp, _, err = raw.ReadTCPLayer()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				continue
			}
		}
		if tcp.chkFlag(SYN | ACK) {
			// raw.ackn = tcp.Seq + 1
			layer.tcp.ackn = ackn
			layer.tcp.seqn = seqn
			err = raw.sendAck()
			if err != nil {
				return
			}
			continue
		}
		n := len(tcp.payload)
		if tcp.chkFlag(PSH|ACK) && n >= TCPLEN && checkTCPOptions(tcp.options) {
			head := string(tcp.payload[:4])
			tail := string(tcp.payload[n-4:])
			if head == "HTTP" && tail == "\r\n\r\n" {
				layer.tcp.ackn = tcp.seqn + uint32(n)
				break
			}
		}
	}
	return
}

type RAWListener struct {
	RAWConn
	newcons map[string]*connInfo
	conns   map[string]*connInfo
	mutex   myMutex
	laddr   *net.UDPAddr
}

func ListenRAW(address string) (listener *RAWListener, err error) {
	udpaddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return
	}
	if udpaddr.IP == nil || udpaddr.IP.Equal(net.IPv4(0, 0, 0, 0)) {
		udpaddr.IP = net.IPv4(127, 0, 0, 1)
	}
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: udpaddr.IP})
	if err != nil {
		return
	}
	wconn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: udpaddr.IP})
	if err != nil {
		return
	}
	if dscp != 0 {
		ipv4.NewConn(wconn).SetTOS(dscp)
	}
	rconn, err := ipv4.NewRawConn(conn)
	fatalErr(err)
	// filter: tcp and src port udpaddr.Port
	rconn.SetBPF([]bpf.RawInstruction{
		{0x30, 0, 0, 0x00000009},
		{0x15, 0, 6, 0x00000006},
		{0x28, 0, 0, 0x00000006},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x00000000},
		{0x48, 0, 0, 0x00000002},
		{0x15, 0, 1, uint32(udpaddr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	})
	listener = &RAWListener{
		RAWConn: RAWConn{
			conn:  conn,
			wconn: wconn,
			rconn: rconn,
			udp:   nil,
			buf:   make([]byte, 65536),
			layer: nil,
		},
		newcons: make(map[string]*connInfo),
		conns:   make(map[string]*connInfo),
		laddr:   udpaddr,
	}
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
		"--sport", strconv.Itoa(udpaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	listener.clean = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
		"--sport", strconv.Itoa(udpaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	return
}

func (listener *RAWListener) doRead(b []byte) (n int, addr *net.UDPAddr, err error) {
	for {
		var tcp *TCPLayer
		var addrstr string
		tcp, addr, err = listener.ReadTCPLayer()
		if addr != nil {
			addrstr = addr.String()
		}
		if tcp != nil && (tcp.chkFlag(RST) || tcp.chkFlag(FIN)) {
			listener.mutex.run(func() {
				delete(listener.newcons, addrstr)
				delete(listener.conns, addrstr)
			})
			continue
		}
		if err != nil {
			return
		}
		var info *connInfo
		var ok bool
		listener.mutex.run(func() {
			info, ok = listener.conns[addrstr]
		})
		n = len(tcp.payload)
		if ok && n != 0 {
			t := info.layer.tcp
			if uint64(tcp.seqn)+uint64(n) > uint64(t.ackn) {
				t.ackn = tcp.seqn + uint32(n)
			}
			//fmt.Println("read from ", addrstr, " to ", tcp.DstPort, " with ", n, " bytes")
			if info.state == HTTPREPSENT {
				if tcp.chkFlag(PSH | ACK) {
					if checkTCPOptions(tcp.options) && n > 20 {
						head := string(tcp.payload[:4])
						tail := string(tcp.payload[n-4:])
						if head == "POST" && tail == "\r\n\r\n" {
							t.ackn = tcp.seqn + uint32(n)
							listener.layer = info.layer
							t.options = getTCPOptions()
							_, err = listener.Write(info.rep)
							t.options = nil
							if err != nil {
								return
							}
						}
					} else {
						info.rep = nil
						info.state = ESTABLISHED
					}
				} else {
					listener.layer = info.layer
					listener.sendFin()
				}
			}
			if info.state == ESTABLISHED {
				copy(b, tcp.payload)
				return
			}
			continue
		}
		if ok && n == 0 {
			continue
		}
		listener.mutex.run(func() {
			info, ok = listener.newcons[addrstr]
		})
		if ok {
			t := info.layer.tcp
			if info.state == SYNRECEIVED {
				if tcp.chkFlag(ACK) && !tcp.chkFlag(PSH|FIN|SYN) {
					t.seqn++
					if noHTTP {
						info.state = ESTABLISHED
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					} else {
						info.state = WAITHTTPREQ
					}
				} else if tcp.chkFlag(SYN) && !tcp.chkFlag(ACK|PSH) {
					listener.layer = info.layer
					err = listener.sendSynAck()
					if err != nil {
						return
					}
				}
			} else if info.state == WAITHTTPREQ {
				if tcp.chkFlag(ACK|PSH) && checkTCPOptions(tcp.options) && n > 20 {
					head := string(tcp.payload[:4])
					tail := string(tcp.payload[n-4:])
					if head == "POST" && tail == "\r\n\r\n" {
						t.ackn = tcp.seqn + uint32(n)
						listener.layer = info.layer
						if info.rep == nil {
							rep := buildHTTPResponse("")
							info.rep = []byte(rep)
						}
						t.options = getTCPOptions()
						_, err = listener.Write(info.rep)
						t.options = nil
						if err != nil {
							return
						}
						info.state = HTTPREPSENT
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					}
				} else if tcp.chkFlag(SYN) && !tcp.chkFlag(ACK|PSH) {
					listener.layer = info.layer
					err = listener.sendSynAck()
					if err != nil {
						return
					}
				}
			}
			continue
		}
		layer := &pktLayers{
			ip4: &IPv4Layer{
				srcip: listener.laddr.IP,
				dstip: addr.IP,
			},
			tcp: &TCPLayer{
				srcPort: listener.laddr.Port,
				dstPort: addr.Port,
				window:  12580,
				ackn:    tcp.seqn + 1,
				data:    make([]byte, 65536),
			},
		}
		if tcp.chkFlag(SYN) && !tcp.chkFlag(ACK|PSH|FIN) {
			info = &connInfo{
				state: SYNRECEIVED,
				layer: layer,
			}
			binary.Read(rand.Reader, binary.LittleEndian, &(info.layer.tcp.seqn))
			listener.layer = info.layer
			err = listener.sendSynAck()
			if err != nil {
				return
			}
			listener.mutex.run(func() {
				listener.newcons[addrstr] = info
			})
		} else {
			listener.layer = layer
			listener.sendFin()
		}
	}
}

func (listener *RAWListener) LocalAddr() net.Addr {
	return listener.laddr
}

func (listener *RAWListener) RemoteAddr() net.Addr {
	return nil
}

func (listener *RAWListener) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = listener.doRead(b)
	return
}

func (listener *RAWListener) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	listener.mutex.Lock()
	info, ok := listener.conns[addr.String()]
	listener.mutex.Unlock()
	if !ok {
		return 0, errors.New("cannot write to " + addr.String())
	}
	listener.layer = info.layer
	n, err = listener.Write(b)
	return
}

type pktLayers struct {
	ip4 *IPv4Layer
	tcp *TCPLayer
}

type connInfo struct {
	state uint32
	layer *pktLayers
	rep   []byte
}

func getTCPOptions() []TCPOption {
	return []TCPOption{
		{
			kind:   TCPOptionKindSACKPermitted,
			length: 2,
		},
	}
}

func checkTCPOptions(options []TCPOption) (ok bool) {
	for _, v := range options {
		if v.kind == TCPOptionKindSACKPermitted {
			ok = true
			break
		}
	}
	return
}

// copy from github.com/google/gopacket/layers/tcp.go

const (
	TCPOptionKindEndList                         = 0
	TCPOptionKindNop                             = 1
	TCPOptionKindMSS                             = 2  // len = 4
	TCPOptionKindWindowScale                     = 3  // len = 3
	TCPOptionKindSACKPermitted                   = 4  // len = 2
	TCPOptionKindSACK                            = 5  // len = n
	TCPOptionKindEcho                            = 6  // len = 6, obsolete
	TCPOptionKindEchoReply                       = 7  // len = 6, obsolete
	TCPOptionKindTimestamps                      = 8  // len = 10
	TCPOptionKindPartialOrderConnectionPermitted = 9  // len = 2, obsolete
	TCPOptionKindPartialOrderServiceProfile      = 10 // len = 3, obsolete
	TCPOptionKindCC                              = 11 // obsolete
	TCPOptionKindCCNew                           = 12 // obsolete
	TCPOptionKindCCEcho                          = 13 // obsolete
	TCPOptionKindAltChecksum                     = 14 // len = 3, obsolete
	TCPOptionKindAltChecksumData                 = 15 // len = n, obsolete
)

const (
	FIN = 1
	SYN = 2
	RST = 4
	PSH = 8
	ACK = 16
	URG = 32

	ECE = 1
	CWR = 2
	NS  = 4
)

const (
	TCPLEN = 20 // FIXME
)

type IPv4Layer struct {
	srcip net.IP
	dstip net.IP
}

type TCPOption struct {
	kind   uint8
	length uint8
	data   []byte
}

type TCPLayer struct {
	srcPort    int
	dstPort    int
	seqn       uint32
	ackn       uint32
	dataOffset uint8 // 4 bits, headerLen = dataOffset << 2
	reserved   uint8 // 3 bits, must be zero
	ecn        uint8 // 3 bits, NS, CWR and ECE
	flags      uint8 // 6 bits, URG, ACK, PSH, RST, SYN and FIN
	window     uint16
	chksum     uint16
	urgent     uint16 // if URG is set
	options    []TCPOption
	opts       [4]TCPOption // pre allocate
	padding    []byte
	pads       [4]byte // pre allocate
	payload    []byte
	data       []byte // if data is not nil, marshal method will use this slice
}

func decodeTCPlayer(data []byte) (tcp *TCPLayer, err error) {
	tcp = &TCPLayer{}
	defer func() {
		if err != nil {
			tcp = nil
		}
	}()

	length := len(data)
	if length < TCPLEN {
		err = fmt.Errorf("Invalid TCP packet length %d < %d", length, TCPLEN)
		return
	}

	tcp.srcPort = int(binary.BigEndian.Uint16(data[:2]))
	tcp.dstPort = int(binary.BigEndian.Uint16(data[2:4]))
	tcp.seqn = binary.BigEndian.Uint32(data[4:8])
	tcp.ackn = binary.BigEndian.Uint32(data[8:12])

	u16 := binary.BigEndian.Uint16(data[12:14])
	tcp.dataOffset = uint8(u16 >> 12)
	tcp.reserved = uint8(u16 >> 9 & (1<<3 - 1))
	tcp.ecn = uint8(u16 >> 6 & (1<<3 - 1))
	tcp.flags = uint8(u16 & (1<<6 - 1))
	if (length >> 2) < int(tcp.dataOffset) {
		err = errors.New("TCP data offset greater than packet length")
		return
	}
	headerLen := int(tcp.dataOffset) << 2

	tcp.window = binary.BigEndian.Uint16(data[14:16])
	tcp.chksum = binary.BigEndian.Uint16(data[16:18])
	tcp.urgent = binary.BigEndian.Uint16(data[18:20])

	if length > headerLen {
		tcp.payload = data[headerLen:]
	}

	if headerLen == TCPLEN {
		return
	}

	data = data[TCPLEN:headerLen]
	for len(data) > 0 {
		if tcp.options == nil {
			tcp.options = tcp.opts[:0]
		}
		tcp.options = append(tcp.options, TCPOption{kind: data[0]})
		opt := &tcp.options[len(tcp.options)-1]
		switch opt.kind {
		case TCPOptionKindEndList:
			opt.length = 1
			tcp.padding = data[1:]
			break
		case TCPOptionKindNop:
			opt.length = 1
		default:
			opt.length = data[1]
			if opt.length < 2 {
				err = fmt.Errorf("Invalid TCP option length %d < 2", opt.length)
				return
			} else if int(opt.length) > len(data) {
				err = fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.length, len(data))
				return
			}
			opt.data = data[2:opt.length]
		}
		data = data[opt.length:]
	}

	return
}

func (tcp *TCPLayer) marshal(srcip, dstip net.IP) (data []byte) {
	tcp.padding = nil

	headerLen := TCPLEN
	for _, v := range tcp.options {
		switch v.kind {
		case TCPOptionKindEndList, TCPOptionKindNop:
			headerLen++
		default:
			v.length = uint8(len(v.data) + 2)
			headerLen += int(v.length)
		}
	}
	if rem := headerLen % 4; rem != 0 {
		tcp.padding = tcp.pads[:4-rem]
		headerLen += len(tcp.padding)
	}

	if len(tcp.data) >= len(tcp.payload)+headerLen {
		data = tcp.data
	} else {
		data = make([]byte, len(tcp.payload)+headerLen)
	}

	binary.BigEndian.PutUint16(data, uint16(tcp.srcPort))
	binary.BigEndian.PutUint16(data[2:], uint16(tcp.dstPort))
	binary.BigEndian.PutUint32(data[4:], tcp.seqn)
	binary.BigEndian.PutUint32(data[8:], tcp.ackn)

	var u16 uint16
	tcp.dataOffset = uint8(headerLen / 4)
	u16 = uint16(tcp.dataOffset) << 12
	u16 |= uint16(tcp.reserved) << 9
	u16 |= uint16(tcp.ecn) << 6
	u16 |= uint16(tcp.flags)
	binary.BigEndian.PutUint16(data[12:], u16)

	binary.BigEndian.PutUint16(data[14:], tcp.window)
	binary.BigEndian.PutUint16(data[18:], tcp.urgent)

	start := 20
	for _, v := range tcp.options {
		data[start] = byte(v.kind)
		switch v.kind {
		case TCPOptionKindEndList, TCPOptionKindNop:
			start++
		default:
			data[start+1] = v.length
			copy(data[start+2:start+len(v.data)+2], v.data)
			start += int(v.length)
		}
	}
	copy(data[start:], tcp.padding)
	start += len(tcp.padding)
	copy(data[start:], tcp.payload)
	binary.BigEndian.PutUint16(data[16:], 0)
	data = data[:start+len(tcp.payload)]
	binary.BigEndian.PutUint16(data[16:], csum(data, srcip, dstip))
	return
}

func (tcp *TCPLayer) setFlag(flag uint8) {
	tcp.flags |= flag
}

func (tcp *TCPLayer) chkFlag(flag uint8) bool {
	return tcp.flags&flag == flag
}

func csum(data []byte, srcip, dstip net.IP) uint16 {
	srcip = srcip.To4()
	dstip = dstip.To4()
	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0, // reserved
		6, // tcp protocol number
		0, 0,
	}
	binary.BigEndian.PutUint16(pseudoHeader[10:], uint16(len(data)))

	var sum uint32

	f := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 != 0 {
			sum += uint32(binary.BigEndian.Uint16([]byte{b[len(b)-1], 0}))
		}
	}

	f(pseudoHeader)
	f(data)

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(^sum)
}
