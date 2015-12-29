package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"tls/protocol"
)

func sender(conn net.Conn) {
	for i := 0; i < 1000; i++ {
		words := fmt.Sprintf("{\"Id\":%d,\"Name\":\"golang\",\"Message\":\"message\"}", i)
		conn.Write(protocol.Packet([]byte(words)))
	}
	fmt.Println("send over")
}

func main() {
	cert2_b, _ := ioutil.ReadFile("cert2.pem")
	priv2_b, _ := ioutil.ReadFile("cert2.key")
	priv2, _ := x509.ParsePKCS1PrivateKey(priv2_b)

	cert := tls.Certificate{
		Certificate: [][]byte{cert2_b},
		PrivateKey:  priv2,
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:10443", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		log.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		log.Println("===")
		log.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
	go sender(conn)
	for {
		time.Sleep(1 * 1e9)
	}

}
