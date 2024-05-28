package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/tmdgusya/law-level-tcp-ip/data"
)

func main() {
	srcIP := net.ParseIP("127.0.0.1").To4()
	dstIP := net.ParseIP("127.0.0.1").To4()
	srcPort := uint16(12345)
	dstPort := uint16(8080)
	message := []byte("Hello, TCP!")

	rawConn, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatal("Error creating raw socket:", err)
	}
	defer syscall.Close(rawConn)

	// Send data packet
	packet := data.BuildTCPPacket(srcIP, dstIP, srcPort, dstPort, 0, 0, 0x18, message) // PSH and ACK flags
	err = data.SendTCPPacket(rawConn, packet, "127.0.0.1", dstPort)
	if err != nil {
		log.Fatal("Error sending data packet:", err)
	}
	fmt.Println("Data packet sent")
}

func calculateChecksum(data []byte) uint16 {
	sum := 0
	for i := 0; i < len(data)-1; i += 2 {
		sum += int(binary.BigEndian.Uint16(data[i : i+2]))
		if sum > 0xffff {
			sum -= 0xffff
		}
	}
	return uint16(^sum)
}
