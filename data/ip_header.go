package data

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

/*
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type IPHeader struct {
	Version        uint8
	IHL            uint8
	TOS            uint8
	Length         uint16
	ID             uint16
	Flags          uint8
	FragmentOffSet uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
}

type TCPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	DataOff  uint8
	Flags    uint8
	WinSize  uint16
	Checksum uint16
	UrgPtr   uint16
}

func (tcp *TCPHeader) Marshal() []byte {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], tcp.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], tcp.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], tcp.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], tcp.AckNum)
	buf[12] = tcp.DataOff << 4
	buf[13] = tcp.Flags
	binary.BigEndian.PutUint16(buf[14:16], tcp.WinSize)
	binary.BigEndian.PutUint16(buf[16:18], tcp.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], tcp.UrgPtr)
	return buf
}

func ParseIPHeader(data []byte) IPHeader {
	return IPHeader{
		Version:        data[0] >> 4,
		IHL:            data[0] & 0x0F,
		TOS:            data[1],
		Length:         binary.BigEndian.Uint16(data[2:4]),
		ID:             binary.BigEndian.Uint16(data[4:6]),
		Flags:          data[6] >> 5,
		FragmentOffSet: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:            data[8],
		Protocol:       data[9],
		Checksum:       binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IPv4(data[12], data[13], data[14], data[15]),
		DstIP:          net.IPv4(data[16], data[17], data[18], data[19]),
	}
}

func ParseTCPHeader(data []byte) TCPHeader {
	return TCPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		SeqNum:   binary.BigEndian.Uint32(data[4:8]),
		AckNum:   binary.BigEndian.Uint32(data[8:12]),
		DataOff:  data[12] >> 4,
		Flags:    data[13],
		WinSize:  binary.BigEndian.Uint16(data[14:16]),
		Checksum: binary.BigEndian.Uint16(data[16:18]),
		UrgPtr:   binary.BigEndian.Uint16(data[18:20]),
	}
}

func CalculateChecksum(data []byte) uint16 {
	sum := 0
	for i := 0; i < len(data)-1; i += 2 {
		sum += int(binary.BigEndian.Uint16(data[i : i+2]))
		if sum > 0xffff {
			sum -= 0xffff
		}
	}
	return uint16(^sum)
}

func BuildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum, ackNum uint32, flags uint8, data []byte) []byte {
	fmt.Printf("Ack Num : %d\n", flags)
	// Build TCP Header
	tcp := TCPHeader{
		SrcPort: srcPort,
		DstPort: dstPort,
		SeqNum:  seqNum,
		AckNum:  ackNum,
		DataOff: 5,
		Flags:   flags,
		WinSize: 1024,
	}

	// Build IP Header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0x00
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(40+len(data)))
	binary.BigEndian.PutUint16(ipHeader[4:6], 0)
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)
	ipHeader[8] = 64
	ipHeader[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	// Calculate IP Checksum
	checksum := CalculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	// Combine IP Header and TCP Header
	packet := append(ipHeader, tcp.Marshal()...)
	packet = append(packet, data...)

	return packet
}

func SendTCPPacket(rawConn int, packet []byte, destIP string, destPort uint16) error {
	addr := syscall.SockaddrInet4{Port: int(destPort)}
	copy(addr.Addr[:], net.ParseIP(destIP).To4())
	return syscall.Sendto(rawConn, packet, 0, &addr)
}
