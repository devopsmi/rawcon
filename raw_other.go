// +build !linux

package rawcon

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type RAWConn struct {
	udp     net.Conn
	handle  *pcap.Handle
	pktsrc  *gopacket.PacketSource
	opts    gopacket.SerializeOptions
	buffer  gopacket.SerializeBuffer
	packets chan gopacket.Packet
	rtimer  *time.Timer
	wtimer  *time.Timer
	layer   *pktLayers
}

func (conn *RAWConn) readLayers() (layer *pktLayers, err error) {
	for {
		var packet gopacket.Packet
		if conn.rtimer != nil {
			select {
			case <-conn.rtimer.C:
				err = &timeoutErr{
					op: "read from " + conn.RemoteAddr().String(),
				}
				return
			case packet = <-conn.packets:
			}
		} else {
			packet = <-conn.packets
		}
		//log.Println(packet)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth, _ := ethLayer.(*layers.Ethernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip4, _ := ipLayer.(*layers.IPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if ignrst && tcp.RST {
			continue
		}
		layer = &pktLayers{
			eth: eth, ip4: ip4, tcp: tcp,
		}
		return
	}
}

func (conn *RAWConn) close() (err error) {
	if conn.udp != nil && conn.handle != nil {
		conn.sendFin()
	}
	if conn.udp != nil {
		err = conn.udp.Close()
	}
	if conn.handle != nil {
		conn.handle.Close()
	}
	return
}

func (conn *RAWConn) Close() (err error) {
	return conn.close()
}

func (conn *RAWConn) sendPacket() (err error) {
	buffer := gopacket.NewSerializeBuffer()
	opts := conn.opts
	layer := conn.layer
	layer.ip4.Id++
	layer.tcp.SetNetworkLayerForChecksum(layer.ip4)
	err = gopacket.SerializeLayers(buffer, opts,
		layer.eth, layer.ip4,
		layer.tcp, gopacket.Payload(layer.tcp.Payload))
	if err == nil {
		err = conn.handle.WritePacketData(buffer.Bytes())
	}
	return
}

func (conn *RAWConn) updateTCP() {
	tcp := conn.layer.tcp
	tcp.Padding = nil
	tcp.FIN = false
	tcp.PSH = false
	tcp.ACK = false
	tcp.RST = false
	tcp.SYN = false
}

func (conn *RAWConn) sendSyn() (err error) {
	conn.updateTCP()
	tcp := conn.layer.tcp
	tcp.SYN = true
	options := tcp.Options
	defer func() {
		tcp.Options = options
	}()
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	return conn.sendPacket()
}

func (conn *RAWConn) sendSynAck() (err error) {
	conn.updateTCP()
	tcp := conn.layer.tcp
	tcp.SYN = true
	tcp.ACK = true
	options := tcp.Options
	defer func() {
		tcp.Options = options
	}()
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	return conn.sendPacket()
}

func (conn *RAWConn) sendAck() (err error) {
	conn.updateTCP()
	conn.layer.tcp.ACK = true
	return conn.sendPacket()
}

func (conn *RAWConn) sendFin() (err error) {
	conn.updateTCP()
	conn.layer.tcp.FIN = true
	return conn.sendPacket()
}

func (conn *RAWConn) sendRst() (err error) {
	conn.updateTCP()
	conn.layer.tcp.RST = true
	return conn.sendPacket()
}

func (conn *RAWConn) Write(b []byte) (n int, err error) {
	n = len(b)
	conn.updateTCP()
	tcp := conn.layer.tcp
	tcp.PSH = true
	tcp.ACK = true
	tcp.Payload = b
	defer func() {
		tcp.Payload = nil
		tcp.Seq += uint32(n)
	}()
	return n, conn.sendPacket()
}

func (conn *RAWConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	defer func() {
		if conn.rtimer != nil {
			conn.rtimer.Stop()
			conn.rtimer = nil
		}
	}()
	for {
		var layer *pktLayers
		layer, err = conn.readLayers()
		if err != nil {
			return
		}
		ip4 := layer.ip4
		tcp := layer.tcp
		if tcp.SYN && tcp.ACK {
			err = conn.sendAck()
			if err != nil {
				return
			} else {
				continue
			}
		}
		n = len(tcp.Payload)
		if n == 0 {
			continue
		}
		if conn.udp != nil {
			addr = conn.RemoteAddr()
		} else {
			addr = &net.UDPAddr{
				IP:   ip4.SrcIP,
				Port: int(tcp.SrcPort),
			}
		}
		conn.layer.tcp.Ack += uint32(n)
		if uint64(tcp.Seq)+uint64(n) > uint64(conn.layer.tcp.Ack) {
			conn.layer.tcp.Ack = tcp.Seq + uint32(n)
		}
		copy(b, tcp.Payload)
		return
	}
}

func (conn *RAWConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	uaddr := addr.(*net.UDPAddr)
	conn.layer.ip4.DstIP = uaddr.IP
	conn.layer.tcp.DstPort = layers.TCPPort(uaddr.Port)
	return conn.Write(b)
}

func (conn *RAWConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFrom(b)
	return
}

func (conn *RAWConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.SrcIP,
		Port: int(conn.layer.tcp.SrcPort),
	}
}

func (conn *RAWConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.DstIP,
		Port: int(conn.layer.tcp.DstPort),
	}
}

func (conn *RAWConn) SetReadDeadline(t time.Time) (err error) {
	if conn.rtimer != nil {
		conn.rtimer.Stop()
	}
	conn.rtimer = time.NewTimer(t.Sub(time.Now()))
	return
}

func (conn *RAWConn) SetWriteDeadline(t time.Time) (err error) {
	if conn.wtimer != nil {
		conn.wtimer.Stop()
	}
	conn.wtimer = time.NewTimer(t.Sub(time.Now()))
	return
}

func (conn *RAWConn) SetDeadline(t time.Time) (err error) {
	err = conn.SetReadDeadline(t)
	if err == nil {
		err = conn.SetWriteDeadline(t)
	}
	return
}

func DialRAW(address string) (conn *RAWConn, err error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	udp, err := net.Dial("udp4", address)
	if err != nil {
		return
	}
	ulocaladdr := udp.LocalAddr().(*net.UDPAddr)
	localaddr := &net.IPAddr{IP: ulocaladdr.IP}
	uremoteaddr := udp.RemoteAddr().(*net.UDPAddr)
	remoteaddr := &net.IPAddr{IP: uremoteaddr.IP}
	var ifaceName string
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			if addr.IP.Equal(ulocaladdr.IP) {
				ifaceName = iface.Name
			}
		}
	}
	if len(ifaceName) == 0 {
		err = errors.New("cannot find correct interface")
		return
	}
	handle, err := pcap.OpenLive(ifaceName, 65536, true, time.Millisecond)
	if err != nil {
		return
	}
	buf := make([]byte, 32)
	binary.Read(rand.Reader, binary.LittleEndian, buf)
	uconn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(8, 8, buf[0], buf[1]), Port: int(binary.LittleEndian.Uint16(buf[2:4]))})
	if err != nil {
		return
	}
	defer uconn.Close()
	filter := "udp and src port " + strconv.Itoa(uconn.LocalAddr().(*net.UDPAddr).Port) +
		" and dst host " + uconn.RemoteAddr().(*net.UDPAddr).IP.String() +
		" and dst port " + strconv.Itoa(uconn.RemoteAddr().(*net.UDPAddr).Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return
	}
	pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := pktsrc.Packets()
	_, err = uconn.Write(buf)
	if err != nil {
		return
	}
	var eth *layers.Ethernet
	timer := time.NewTimer(time.Second * 2)
	select {
	case <-timer.C:
		err = errors.New("timeout")
		return
	case packet := <-packets:
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			return
		}
		eth, _ = ethLayer.(*layers.Ethernet)
	}
	filter = "tcp and src host " + remoteaddr.String() +
		" and src port " + strconv.Itoa(uremoteaddr.Port) +
		" and dst host " + localaddr.String() +
		" and dst port " + strconv.Itoa(ulocaladdr.Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return
	}
	conn = &RAWConn{
		udp:     udp,
		buffer:  gopacket.NewSerializeBuffer(),
		handle:  handle,
		pktsrc:  pktsrc,
		packets: packets,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		layer: &pktLayers{
			eth: eth,
			ip4: &layers.IPv4{
				SrcIP:    localaddr.IP,
				DstIP:    remoteaddr.IP,
				Protocol: layers.IPProtocolTCP,
				Version:  0x4,
				Id:       uint16(src.Int63() % 65536),
				Flags:    layers.IPv4DontFragment,
				TTL:      0x40,
				TOS:      uint8(dscp),
			},
			tcp: &layers.TCP{
				SrcPort: layers.TCPPort(ulocaladdr.Port),
				DstPort: layers.TCPPort(uremoteaddr.Port),
				Window:  12580,
				Ack:     0,
			},
		},
	}
	tcp := conn.layer.tcp
	var cl *pktLayers
	binary.Read(rand.Reader, binary.LittleEndian, &(conn.layer.tcp.Seq))
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	retry := 0
	var ackn uint32
	var seqn uint32
	defer func() {
		conn.rtimer = nil
	}()
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		err = conn.sendSyn()
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(time.Second * 1))
		cl, err = conn.readLayers()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				continue
			}
		}
		if cl.tcp.SYN && cl.tcp.ACK {
			tcp.Ack = cl.tcp.Seq + 1
			tcp.Seq++
			ackn = tcp.Ack
			seqn = tcp.Seq
			err = conn.sendAck()
			if err != nil {
				return
			}
		}
		break
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
		tcp.Options = opt
		tcp.Seq = seqn
		_, err = conn.Write([]byte(req))
		if err != nil {
			return
		}
		tcp.Options = nil
		err = conn.SetReadDeadline(time.Now().Add(time.Second * 1))
		if err != nil {
			return
		}
		cl, err = conn.readLayers()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				continue
			}
		}
		if cl.tcp.SYN && cl.tcp.ACK {
			tcp.Ack = ackn
			tcp.Seq = seqn
			err = conn.sendAck()
			if err != nil {
				return
			}
			continue
		}
		n := len(cl.tcp.Payload)
		if cl.tcp.PSH && cl.tcp.ACK && n >= 20 && checkTCPOptions(cl.tcp.Options) {
			head := string(cl.tcp.Payload[:4])
			tail := string(cl.tcp.Payload[n-4:])
			if head == "HTTP" && tail == "\r\n\r\n" {
				tcp.Ack = cl.tcp.Seq + uint32(n)
				break
			}
		}
	}
	return
}

func chooseInterfaceByAddr(addr string) (in pcap.Interface, err error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		for _, address := range iface.Addresses {
			if address.IP.String() == addr {
				in = iface
				return
			}
		}
	}
	err = errors.New("incorrect bind address")
	return
}

type RAWListener struct {
	RAWConn
	newcons map[string]*connInfo
	conns   map[string]*connInfo
	mutex   myMutex
	laddr   *net.IPAddr
	lport   int
}

func (listener *RAWListener) Close() (err error) {
	conn := listener
	if conn != nil {
		listener.mutex.run(func() {
			for _, v := range listener.newcons {
				listener.closeConn(v)
			}
			for _, v := range listener.conns {
				listener.closeConn(v)
			}
		})
	}
	return conn.close()
}

func (listener *RAWListener) closeConn(info *connInfo) (err error) {
	listener.layer = info.layer
	return listener.sendFin()
}

func ListenRAW(address string) (listener *RAWListener, err error) {
	udp, err := net.Dial("udp4", address)
	if err != nil {
		return
	}
	udpaddr := udp.LocalAddr().(*net.UDPAddr)
	err = udp.Close()
	if err != nil {
		return
	}
	in, err := chooseInterfaceByAddr(udpaddr.IP.String())
	if err != nil {
		return
	}
	handle, err := pcap.OpenLive(in.Name, 65536, true, time.Millisecond*1)
	if err != nil {
		return
	}
	filter := "tcp and dst host " + udpaddr.IP.String() +
		" and dst port " + strconv.Itoa(udpaddr.Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return
	}
	pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	listener = &RAWListener{
		laddr: &net.IPAddr{IP: udpaddr.IP},
		lport: udpaddr.Port,
		RAWConn: RAWConn{
			buffer:  gopacket.NewSerializeBuffer(),
			handle:  handle,
			pktsrc:  pktsrc,
			packets: pktsrc.Packets(),
			opts: gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			},
		},
		newcons: make(map[string]*connInfo),
		conns:   make(map[string]*connInfo),
	}
	return
}

func (listener *RAWListener) closeConnByAddr(addrstr string) (err error) {
	info, ok := listener.newcons[addrstr]
	if ok {
		delete(listener.newcons, addrstr)
	} else {
		info, ok = listener.conns[addrstr]
		if ok {
			delete(listener.conns, addrstr)
		}
	}
	if info != nil {
		err = listener.closeConn(info)
	}
	return
}

func (listener *RAWListener) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		var cl *pktLayers
		cl, err = listener.readLayers()
		if err != nil {
			return
		}
		tcp := cl.tcp
		listener.layer = nil
		uaddr := &net.UDPAddr{
			IP:   cl.ip4.SrcIP,
			Port: int(tcp.SrcPort),
		}
		addr = uaddr
		addrstr := uaddr.String()
		if (tcp.RST) || tcp.FIN {
			listener.mutex.run(func() {
				err = listener.closeConnByAddr(addrstr)
			})
			if err != nil {
				return
			}
			continue
		}
		var info *connInfo
		var ok bool
		listener.mutex.run(func() {
			info, ok = listener.conns[addrstr]
		})
		n = len(tcp.Payload)
		if ok && n != 0 {
			if uint64(tcp.Seq)+uint64(n) > uint64(info.layer.tcp.Ack) {
				info.layer.tcp.Ack = tcp.Seq + uint32(n)
			}
			if info.state == HTTPREPSENT {
				if tcp.PSH && tcp.ACK {
					info.rep = nil
					info.state = ESTABLISHED
				} else {
					if tcp.PSH && tcp.ACK && checkTCPOptions(tcp.Options) && n > 20 {
						head := string(tcp.Payload[:4])
						tail := string(tcp.Payload[n-4:])
						if head == "POST" && tail == "\r\n\r\n" {
							//info.tcp.tcp.Ack = tcp.Seq + 1
							info.layer.tcp.Ack = tcp.Seq + uint32(n)
							listener.layer = info.layer
							listener.layer.tcp.Options = getTCPOptions()
							_, err = listener.Write(info.rep)
							listener.layer.tcp.Options = nil
							if err != nil {
								return
							}
						}
					}
					listener.layer = info.layer
					listener.sendFin()
					continue
				}
			}
			if info.state == ESTABLISHED {
				copy(b, tcp.Payload)
				return
			}
			continue
		}
		listener.mutex.run(func() {
			info, ok = listener.newcons[addrstr]
		})
		if ok {
			if info.state == SYNRECEIVED {
				if tcp.ACK && !tcp.PSH && !tcp.FIN && !tcp.SYN {
					info.layer.tcp.Seq++
					if noHTTP {
						info.state = ESTABLISHED
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					} else {
						info.state = WAITHTTPREQ
					}
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					listener.layer = info.layer
					err = listener.sendSynAck()
					if err != nil {
						return
					}
				}
			} else if info.state == WAITHTTPREQ {
				if tcp.PSH && tcp.ACK && checkTCPOptions(tcp.Options) && n > 20 {
					head := string(tcp.Payload[:4])
					tail := string(tcp.Payload[n-4:])
					if head == "POST" && tail == "\r\n\r\n" {
						info.layer.tcp.Ack += uint32(n)
						listener.layer = info.layer
						if info.rep == nil {
							rep := buildHTTPResponse("")
							info.rep = []byte(rep)
						}
						listener.layer.tcp.Options = getTCPOptions()
						_, err = listener.Write(info.rep)
						if err != nil {
							return
						}
						info.state = HTTPREPSENT
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					}
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					listener.layer = info.layer
					err = listener.sendSynAck()
					if err != nil {
						return
					}
				}
			}
			continue
		}
		eth := &layers.Ethernet{
			DstMAC:       cl.eth.SrcMAC,
			SrcMAC:       cl.eth.DstMAC,
			EthernetType: cl.eth.EthernetType,
		}
		ip4 := &layers.IPv4{
			SrcIP:    cl.ip4.DstIP,
			DstIP:    cl.ip4.SrcIP,
			Protocol: layers.IPProtocolTCP,
			Version:  0x4,
			Id:       uint16(src.Int63() % 65536),
			Flags:    layers.IPv4DontFragment,
			TTL:      0x40,
			TOS:      uint8(dscp),
		}
		tcp = &layers.TCP{
			SrcPort: cl.tcp.DstPort,
			DstPort: cl.tcp.SrcPort,
			Window:  12580,
			Ack:     cl.tcp.Seq + 1,
		}
		layer := &pktLayers{
			eth: eth,
			ip4: ip4,
			tcp: tcp,
		}
		if tcp.SYN && !tcp.ACK && !tcp.PSH && !tcp.FIN {
			info := &connInfo{
				state: SYNRECEIVED,
				layer: layer,
			}
			binary.Read(rand.Reader, binary.LittleEndian, &(info.layer.tcp.Seq))
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

func (listener *RAWListener) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   listener.laddr.IP,
		Port: listener.lport,
	}
}

// FIXME
type pktLayers struct {
	eth *layers.Ethernet
	ip4 *layers.IPv4
	tcp *layers.TCP
}

func getTCPOptions() []layers.TCPOption {
	return []layers.TCPOption{
		layers.TCPOption{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
	}
}

func checkTCPOptions(options []layers.TCPOption) (ok bool) {
	for _, v := range options {
		if v.OptionType == layers.TCPOptionKindSACKPermitted {
			ok = true
			break
		}
	}
	return
}

type connInfo struct {
	state uint32
	layer *pktLayers
	rep   []byte
}
