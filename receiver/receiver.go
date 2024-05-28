package main

import (
	"fmt"
	"log"
	"syscall"

	"github.com/tmdgusya/law-level-tcp-ip/data"
)

func receivePackets() {
	rawConn, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatal("Error creating raw socket:", err)
	}
	defer syscall.Close(rawConn)

	buffer := make([]byte, 4096)
	for {
		n, addr, err := syscall.Recvfrom(rawConn, buffer, 0)
		if err != nil {
			log.Fatal("Error receiving packet:", err)
		}

		ipHeader := data.ParseIPHeader(buffer[:20])
		tcpHeader := data.ParseTCPHeader(buffer[20:n])

		if ipHeader.DstIP.String() == "127.0.0.1" {
			fmt.Printf("Received packet from %v\n", addr)
			fmt.Printf("IP Header: %+v\n", ipHeader)
			fmt.Printf("TCP Header: %+v\n", tcpHeader)
			fmt.Printf("Message : %s\n", string(buffer[40:n]))
		}
	}
}

func main() {
	receivePackets()
}
