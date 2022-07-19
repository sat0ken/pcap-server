package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
)

const serverPort = 18443

type AllPackets struct {
	client [][]byte
	server [][]byte
}

func readPcap() AllPackets {
	var clientPacket, serverPacket [][]byte

	handle, err := pcap.OpenOffline("./local-http3.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//fmt.Printf("packet is %x\n", packet.ApplicationLayer().Payload())
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == serverPort {
			serverPacket = append(serverPacket, udp.Payload)
		} else {
			clientPacket = append(clientPacket, udp.Payload)
		}
	}
	return AllPackets{
		client: clientPacket,
		server: serverPacket,
	}
}

func main() {
	packet := readPcap()

	udpAddr := net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: serverPort,
	}
	udpLn, err := net.ListenUDP("udp", &udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1500)
	fmt.Println("start pcap server by udp ...")
	for {
		var i int
		n, client, err := udpLn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			//fmt.Printf("recv packet is %x\n", buf[:n])
			//fmt.Printf("client packet is %x\n", packet.client[i])
			if bytes.Equal(buf[:n], packet.client[i]) {
				fmt.Printf("writet packet is %x\n", packet.server[i])
				udpLn.WriteTo(packet.server[i], client)
			}
			i++
		}()
	}
}
