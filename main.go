package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// HTTPTunnel structure handle all the global variables for HTTP Tunnel
type HTTPTunnel struct {
	payload    string
	auth       string
	rp         string
	lp         string
	connect    chan *Client
	disconnect chan *Client
	clients    map[*Client]bool
	tunType    string
	SNI        string
}

// Proxy handle the connection to remote proxy using socket/net of HTTP Tunnel
type Proxy struct {
	socket    net.Conn
	conn      *tls.Conn
	connected bool
}

// Client handle the client connecting on the HTTP Tunnel
type Client struct {
	socket   net.Conn
	proxy    Proxy
	hostPort []string
	proto    string
}

var (
	maxBuffer = 65535
)

func (tun *HTTPTunnel) start() {
	log.Println("Server running on local:", tun.lp)
	log.Println("Server running on proxy:", tun.rp)

	if strings.ToLower(tun.tunType) == "http" {
		log.Println("Payload:", string(tun.payload))
	} else if strings.ToLower(tun.tunType) == "ssl" {
		log.Println("SNI:", string(tun.SNI))
	}

	for {
		select {
		case conn := <-tun.connect:
			tun.clients[conn] = true
			log.Println("Client connected:", conn.socket.RemoteAddr())
		case conn := <-tun.disconnect:
			delete(tun.clients, conn)
			log.Println("Client disconnected", conn.socket.RemoteAddr())
		}

	}
}
func (tun *HTTPTunnel) isHTTPRequest(request string) bool {
	if strings.Contains(request, "CONNECT") ||
		strings.Contains(request, "GET") ||
		strings.Contains(request, "POST") ||
		strings.Contains(request, "PUT") ||
		strings.Contains(request, "OPTIONS") ||
		strings.Contains(request, "TRACE") ||
		strings.Contains(request, "TRACE") ||
		strings.Contains(request, "OPTIONS") ||
		strings.Contains(request, "TRACE") ||
		strings.Contains(request, "PATCH") ||
		strings.Contains(request, "DELETE") {
		return true
	}
	return false
}
func (tun *HTTPTunnel) receiveHTTPMsg(r net.Conn) string {
	data := ""
	buffer := make([]byte, maxBuffer)
	for {
		length, err := r.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}

			break
		}
		data += string(buffer[:length])
		if strings.HasSuffix(data, "\r\n\r\n") {
			break
		}
	}
	return data
}

func (tun *HTTPTunnel) getNetData(request string) string {
	netdata := strings.Split(request, "\r\n")
	return netdata[0]
}
func (tun *HTTPTunnel) getRequestProtocol(request string) string {
	netdata := tun.getNetData(request)
	return strings.Split(netdata, " ")[0]
}
func (tun *HTTPTunnel) getHostPort(request string) []string {
	netdata := tun.getNetData(request)
	tmpHostPort := strings.Split(netdata, " ")
	hostport := strings.Split(tmpHostPort[1], ":")
	return hostport
}

func (tun *HTTPTunnel) getParsePayload(client *Client) string {
	parsed := tun.payload
	parsed = strings.ReplaceAll(parsed, "[raw]", "[method] [host_port] [protocol]")
	parsed = strings.ReplaceAll(parsed, "[real_raw]", "[raw][crlf][crlf]")
	parsed = strings.ReplaceAll(parsed, "[method]", "CONNECT")
	parsed = strings.ReplaceAll(parsed, "[host_port]", "[host]:[port]")
	parsed = strings.ReplaceAll(parsed, "[host]", client.hostPort[0])
	parsed = strings.ReplaceAll(parsed, "[port]", client.hostPort[1])

	if tun.auth == "" { //support the proxy authentication
		parsed = strings.ReplaceAll(parsed, "[protocol]", client.proto)
	} else {
		parsed = strings.ReplaceAll(parsed, "[protocol]", client.proto+"[crlf]"+"Authorization: Basic "+tun.auth)
	}
	parsed = strings.ReplaceAll(parsed, "[user-agent]", "Nakz HTTP Injector")
	parsed = strings.ReplaceAll(parsed, "[close]", "Connection: Close")
	parsed = strings.ReplaceAll(parsed, "[crlf]", "[cr][lf]")
	parsed = strings.ReplaceAll(parsed, "[lfcr]", "[lf][cr]")
	parsed = strings.ReplaceAll(parsed, "[cr]", "\r")
	parsed = strings.ReplaceAll(parsed, "[lf]", "\n")
	return parsed
}

// Handle ...
func (tun *HTTPTunnel) Handle(w io.Writer, r io.Reader, done chan bool) {
	io.Copy(w, r)
	done <- true
}

// HTTPTunnelHandler handle the thread for http packet
func (tun *HTTPTunnel) HTTPTunnelHandler(client *Client) {
	decodedPayload := tun.getParsePayload(client)
	if strings.Contains(decodedPayload, "[split]") || strings.Contains(decodedPayload, "[instant_split]") {
		decodedPayload := strings.ReplaceAll(decodedPayload, "[instant_split]", "[split]")
		decodedPayloadSplit := strings.Split(decodedPayload, "[split]")
		for _, value := range decodedPayloadSplit {
			//fmt.Println("Split", value)
			client.proxy.socket.Write([]byte(value))
		}
	} else if strings.Contains(decodedPayload, "[delay_split]") {
		decodedPayloadSplit := strings.Split(decodedPayload, "[delay_split]")
		for _, value := range decodedPayloadSplit {
			time.Sleep(100 * time.Millisecond)
			//fmt.Println("Delay Split\n", value)
			client.proxy.socket.Write([]byte(value))
		}
	} else {
		client.proxy.socket.Write([]byte(decodedPayload))
	}

	res := tun.receiveHTTPMsg(client.proxy.socket)
	if strings.Contains(strings.ToLower(res), "200 connection established") {
		tun.Handler(client, res)
	} else {
		log.Println("Server Response: ", client.socket.RemoteAddr(), "->", client.proxy.socket.RemoteAddr(), "->", tun.getNetData(res))
		tun.disconnect <- client
	}

}

// SSLTunnelHandler handle the thread for ssl packet
func (tun *HTTPTunnel) SSLTunnelHandler(client *Client) {
	//client.socket.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	defer client.proxy.conn.Close()
	tun.Handler(client, "HTTP/1.0 200 Connection established")
}

// Handler ...
func (tun *HTTPTunnel) Handler(client *Client, res string) {
	client.socket.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	done := make(chan bool)
	if strings.ToLower(tun.tunType) == "ssl" {
		go tun.Transfer(client.proxy.conn, client.socket, done)
		go tun.Transfer(client.socket, client.proxy.conn, done)
		log.Println("Server Response: ", client.socket.RemoteAddr(), "->", client.proxy.conn.RemoteAddr(), "->", tun.getNetData(res))
	} else {
		go tun.Transfer(client.proxy.socket, client.socket, done)
		go tun.Transfer(client.socket, client.proxy.socket, done)
		if strings.Contains(strings.ToLower(res), "mismatch") {
			log.Println("Server Response: ", client.socket.RemoteAddr(), "->", client.proxy.socket.RemoteAddr(), "-> Protocol Mismatch.")
		} else {
			log.Println("Server Response: ", client.socket.RemoteAddr(), "->", client.proxy.socket.RemoteAddr(), "->", tun.getNetData(res))
		}

	}
	if <-done == true { //this return true if someone disconnected
		tun.disconnect <- client
	}
}

// Transfer the packet from both client and server socket
func (tun *HTTPTunnel) Transfer(w io.Writer, r io.Reader, done chan bool) {
	io.Copy(w, r)
	done <- true //send true to channel if transfer is done
}

func (tun *HTTPTunnel) accept(accept net.Conn) {

	req := tun.receiveHTTPMsg(accept)
	if !tun.isHTTPRequest(req) {
		log.Println("Method is not allowed")
		//tun.disconnect <- client
	} else {
		//netData := tun.getNetData(res)
		hostPort := tun.getHostPort(req)
		proto := tun.getRequestProtocol(req)
		if strings.ToLower(tun.tunType) == "http" {
			proxy, err := net.Dial("tcp", tun.rp)
			if err != nil {
				log.Println("Cant connect to proxy")
			}
			client := &Client{
				socket: accept,
				proxy: Proxy{
					socket:    proxy,
					connected: false,
				},
				hostPort: hostPort,
				proto:    proto,
			}
			tun.connect <- client
			tun.HTTPTunnelHandler(client)
		} else if strings.ToLower(tun.tunType) == "ssl" {
			proxy, err := net.Dial("tcp", hostPort[0]+":"+hostPort[1])
			if err != nil {
				log.Println("Cant connect to proxy")
			}
			conn := tls.Client(proxy, &tls.Config{
				ServerName:         tun.SNI,
				InsecureSkipVerify: true,
			})

			client := &Client{
				socket: accept,
				proxy: Proxy{
					conn:      conn,
					connected: false,
				},
			}
			tun.connect <- client
			tun.SSLTunnelHandler(client)
		} else {
			log.Println("HTTP Tunnel Type is not supported.")
			os.Exit(1)
		}
	}
}

func main() {
	errorMsg := ""
	fmt.Println("HTTP Tunneling Client")
	lp := flag.String("lp", "", "Listin Port (required)")
	payload := flag.String("payload", "", "HTTP Payload (optional)")
	rp := flag.String("rp", "", "Remote Proxy [host:port] (optional)")
	rpAuth := flag.String("auth", "", "Remote Proxy Authentication [user:password] (optional)")
	tunType := flag.String("tunType", "", "Tunneling Type [HTTP/SSL] (required)")
	sni := flag.String("sni", "", "Server Name Indication (optional)")

	flag.Parse()

	if *lp == "" || *tunType == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if strings.ToLower(*tunType) == "http" {
		if strings.ToLower(*payload) == "" {
			errorMsg += "Selected Tunnel Type must contain an HTTP Payload\n"
		}
		if strings.ToLower(*rp) == "" {
			errorMsg += "Selected Tunnel Type must contain an Remote Proxy\n"
		}

	} else if strings.ToLower(*tunType) == "ssl" {
		if strings.ToLower(*sni) == "" {
			errorMsg += "Selected Tunnel Type must contain an Server Name Indication (SNI)\n"
		}

	} else {
		errorMsg += "Selected Tunnel Type is not available\n"
	}
	if errorMsg != "" {
		fmt.Println(errorMsg)
		os.Exit(1)
	} else {
		conn, err := net.Listen("tcp", ":"+*lp)
		tun := HTTPTunnel{
			payload:    *payload,
			auth:       base64.StdEncoding.EncodeToString([]byte(*rpAuth)),
			rp:         *rp,
			lp:         *lp,
			connect:    make(chan *Client),
			disconnect: make(chan *Client),
			tunType:    *tunType,
			clients:    make(map[*Client]bool),
			SNI:        *sni,
		}
		go tun.start()

		if err != nil {
			log.Println(err)
		}
		for {
			client, err := conn.Accept()
			if err != nil {
				log.Println(err)
			}
			go tun.accept(client)
		}
	}

}
