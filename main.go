package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	var clientPaket, serverPacket [][]byte

	handle, err := pcap.OpenOffline("./local-http3.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//fmt.Printf("packet is %x\n", packet.ApplicationLayer().Payload())
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		if udp.DstPort == 18443 {
			serverPacket = append(serverPacket, udp.Payload)
		} else {
			clientPaket = append(clientPaket, udp.Payload)
		}
	}
	fmt.Printf("server packet is %x\n", serverPacket)
}
