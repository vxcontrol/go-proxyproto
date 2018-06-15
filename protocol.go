package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	// prefix is the string we look for at the start of a connection
	// to check if this connection is using the proxy protocol
	prefixV1    = []byte("PROXY ")
	prefixV2    = []byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")
	prefixV2Len = len(prefixV2)

	// this also containes version bits which is always 0x2
	commandLocal = byte('\x20')
	commandProxy = byte('\x21')

	addressFamilyUnspec = byte('\x00')
	addressFamilyInet   = byte('\x10')
	addressFamilyInet6  = byte('\x20')
	addressFamilyUnix   = byte('\x30')

	transportProtoUnspec = byte('\x00')
	transportProtoStream = byte('\x01')
	transportProtoDgram  = byte('\x02')

	tcpOverIPV4 = addressFamilyInet | transportProtoStream
	tcpOverIPV6 = addressFamilyInet6 | transportProtoStream
	udpOverIPV4 = addressFamilyInet | transportProtoDgram
	udpOverIPV6 = addressFamilyInet6 | transportProtoDgram

	ErrInvalidUpstream = errors.New("upstream connection address not trusted for PROXY information")
	EnableDebugging    = false
)

// SourceChecker can be used to decide whether to trust the PROXY info or pass
// the original connection address through. If set, the connecting address is
// passed in as an argument. If the function returns an error due to the source
// being disallowed, it should return ErrInvalidUpstream.
//
// If error is not nil, the call to Accept() will fail. If the reason for
// triggering this failure is due to a disallowed source, it should return
// ErrInvalidUpstream.
//
// If bool is true, the PROXY-set address is used.
//
// If bool is false, the connection's remote address is used, rather than the
// address claimed in the PROXY info.
type SourceChecker func(net.Addr) (bool, error)

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol (version 1).
// If the connection is using the protocol, the RemoteAddr() will return
// the correct client address.
//
// Optionally define ProxyHeaderTimeout to set a maximum time to
// receive the Proxy Protocol Header. Zero means no timeout.
type Listener struct {
	Listener           net.Listener
	ProxyHeaderTimeout time.Duration
	SourceCheck        SourceChecker
}

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address.
type Conn struct {
	bufReader          *bufio.Reader
	conn               net.Conn
	dstAddr            *net.TCPAddr
	srcAddr            *net.TCPAddr
	useConnRemoteAddr  bool
	once               sync.Once
	proxyHeaderTimeout time.Duration
}

// Accept waits for and returns the next connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if EnableDebugging {
		log.Debugf("tcp proxy protocol connection accepted from: %v...", conn.RemoteAddr())
	}
	var useConnRemoteAddr bool
	if p.SourceCheck != nil {
		allowed, err := p.SourceCheck(conn.RemoteAddr())
		if err != nil {
			return nil, err
		}
		if !allowed {
			useConnRemoteAddr = true
		}
	}
	newConn := NewConn(conn, p.ProxyHeaderTimeout)
	newConn.useConnRemoteAddr = useConnRemoteAddr
	return newConn, nil
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn, timeout time.Duration) *Conn {
	pConn := &Conn{
		bufReader:          bufio.NewReader(conn),
		conn:               conn,
		proxyHeaderTimeout: timeout,
	}
	return pConn
}

// Read is check for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *Conn) Read(b []byte) (int, error) {
	var err error
	if EnableDebugging {
		log.Debugf("tcp proxy protocol Read...")
	}
	p.once.Do(func() { err = p.checkPrefix() })
	if err != nil {
		return 0, err
	}
	return p.bufReader.Read(b)
}

func (p *Conn) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *Conn) Close() error {
	return p.conn.Close()
}

func (p *Conn) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer. If there is an error parsing the header, the
// address of the client is not returned, and the socket is closed.
// Once implication of this is that the call could block if the
// client is slow. Using a Deadline is recommended if this is called
// before Read()
func (p *Conn) RemoteAddr() net.Addr {
	if EnableDebugging {
		log.Debugf("tcp proxy protocol RemoteAddr...")
	}
	p.once.Do(func() {
		if err := p.checkPrefix(); err != nil && err != io.EOF {
			log.Printf("[ERR] Failed to read proxy prefix: %v", err)
			p.Close()
			p.bufReader = bufio.NewReader(p.conn)
		}
	})
	if p.srcAddr != nil && !p.useConnRemoteAddr {
		return p.srcAddr
	}
	return p.conn.RemoteAddr()
}

func (p *Conn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *Conn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *Conn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *Conn) checkPrefix() error {
	var hdr []byte
	var err error
	var srcIP net.IP
	var dstIP net.IP
	var srcPort int
	var dstPort int

	if EnableDebugging {
		log.Debugf("tcp proxy protocol check prefix, timeout: %v...", p.proxyHeaderTimeout)
	}

	if p.proxyHeaderTimeout != 0 {
		readDeadLine := time.Now().Add(p.proxyHeaderTimeout)
		p.conn.SetReadDeadline(readDeadLine)
		defer p.conn.SetReadDeadline(time.Time{})
	}

	for i := 1; i <= prefixV2Len; i++ {
		var inp []byte
		inp, err = p.bufReader.Peek(i)

		if EnableDebugging {
			log.Debugf("tcp proxy protocol peek(%v): %v...", i, inp)
		}

		if err != nil {
			if EnableDebugging {
				log.Debugf("tcp proxy protocol peek error: %v...", err)
			}
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return nil
			}
			return err
		}

		// Check for a prefix mis-match, quit early
		if !bytes.HasPrefix(prefixV1, inp) && !bytes.HasPrefix(prefixV2, inp) {
			if EnableDebugging {
				log.Debugf("tcp proxy protocol header missing")
			}
			return nil
		} else if bytes.Equal(inp, prefixV1) || bytes.Equal(inp, prefixV2) {
			hdr = inp
			break
		}
	}

	if EnableDebugging {
		log.Debugf("header: % x", hdr)
	}

	if bytes.HasPrefix(hdr, prefixV1) {
		// Version 1 of the protocol
		// Read the header line

		if EnableDebugging {
			log.Debugf("tcp proxy protocol version 1 detected")
		}

		header, err := p.bufReader.ReadString('\n')
		if err != nil {
			p.conn.Close()
			return err
		}

		// Strip the carriage return and new line
		header = header[:len(header)-2]

		// Split on spaces, should be (PROXY <type> <src addr> <dst addr> <src port> <dst port>)
		parts := strings.Split(header, " ")
		if len(parts) != 6 {
			p.conn.Close()
			return fmt.Errorf("Invalid header line: %s", header)
		}

		// Verify the type is known
		switch parts[1] {
		case "TCP4":
		case "TCP6":
		default:
			p.conn.Close()
			return fmt.Errorf("Unhandled address type: %s", parts[1])
		}

		// Parse out the source address
		srcIP = net.ParseIP(parts[2])
		if srcIP == nil {
			p.conn.Close()
			return fmt.Errorf("Invalid source ip: %s", parts[2])
		}
		srcPort, err = strconv.Atoi(parts[4])
		if err != nil {
			p.conn.Close()
			return fmt.Errorf("Invalid source port: %s", parts[4])
		}
		p.srcAddr = &net.TCPAddr{IP: srcIP, Port: srcPort}

		// Parse out the destination address
		dstIP = net.ParseIP(parts[3])
		if dstIP == nil {
			p.conn.Close()
			return fmt.Errorf("Invalid destination ip: %s", parts[3])
		}
		dstPort, err = strconv.Atoi(parts[5])
		if err != nil {
			p.conn.Close()
			return fmt.Errorf("Invalid destination port: %s", parts[5])
		}
		p.dstAddr = &net.TCPAddr{IP: dstIP, Port: dstPort}
	} else if bytes.HasPrefix(hdr, prefixV2) {
		// Version 2 of the protocol

		if EnableDebugging {
			log.Debugf("tcp proxy protocol version 2 detected")
		}

		var b byte
		var signature []byte
		var protocolVersionAndCommand byte
		var transportProtocolAndAddressFamily byte
		var dataLengthB []byte
		var data []byte
		var dataLength uint16

		signature = make([]byte, prefixV2Len)
		dataLengthB = make([]byte, 2)

		// Read signature
		for i := 0; i < prefixV2Len; i++ {
			b, err = p.bufReader.ReadByte()
			if err != nil {
				p.conn.Close()
				return err
			}
			signature[i] = b
		}

		if EnableDebugging {
			log.Debugf("version 2 signature: % x", signature)
		}

		// Read protocol version and command
		b, err = p.bufReader.ReadByte()
		if err != nil {
			p.conn.Close()
			return err
		}
		protocolVersionAndCommand = b

		if EnableDebugging {
			log.Debugf("version 2 protocol version and command: % x", protocolVersionAndCommand)
		}

		if protocolVersionAndCommand != commandProxy {
			p.conn.Close()
			return fmt.Errorf("only version 2 and proxy command is supported, got: % x", protocolVersionAndCommand)
		}

		// Read transport protocol and address family
		b, err = p.bufReader.ReadByte()
		if err != nil {
			p.conn.Close()
			return err
		}
		transportProtocolAndAddressFamily = b

		if EnableDebugging {
			log.Debugf("version 2 protocol transport protocol and address family: % x", transportProtocolAndAddressFamily)
		}

		if transportProtocolAndAddressFamily != tcpOverIPV4 && transportProtocolAndAddressFamily != tcpOverIPV6 &&
			transportProtocolAndAddressFamily != udpOverIPV4 && transportProtocolAndAddressFamily != udpOverIPV6 {
			p.conn.Close()
			return fmt.Errorf("only ipv4 and ipv6 address families supported")
		}

		// Read data length
		for i := 0; i < 2; i++ {
			b, err = p.bufReader.ReadByte()
			if err != nil {
				p.conn.Close()
				return err
			}
			dataLengthB[i] = b
		}

		dataLength = binary.BigEndian.Uint16(dataLengthB)

		if EnableDebugging {
			log.Debugf("version 2 data length: %v", dataLength)
		}

		data = make([]byte, dataLength)
		for i := uint16(0); i < dataLength; i++ {
			b, err = p.bufReader.ReadByte()
			if err != nil {
				p.conn.Close()
				return err
			}
			data[i] = b
		}

		if EnableDebugging {
			log.Debugf("version 2 data hex: % x", data)
			log.Debugf("version 2 data bytes: %v", data)
		}

		if transportProtocolAndAddressFamily&addressFamilyInet == addressFamilyInet {
			srcIP = net.IPv4(data[0], data[1], data[2], data[3])
			srcPort = int(binary.BigEndian.Uint16(data[4:6]))
			dstIP = net.IPv4(data[6], data[7], data[8], data[9])
			dstPort = int(binary.BigEndian.Uint16(data[10:12]))
		} else if transportProtocolAndAddressFamily&addressFamilyInet6 == addressFamilyInet6 {
			srcIP = data[0:16]
			srcPort = int(binary.BigEndian.Uint16(data[16:18]))
			dstIP = data[18:34]
			dstPort = int(binary.BigEndian.Uint16(data[34:36]))
		} else if transportProtocolAndAddressFamily&addressFamilyUnix == addressFamilyUnix {
			p.conn.Close()
			return fmt.Errorf("unix protocol not supported")
		}

		if srcIP == nil || dstIP == nil {
			p.conn.Close()
			return fmt.Errorf("source or destination IP incorrect")
		}

		p.srcAddr = &net.TCPAddr{IP: srcIP, Port: srcPort}
		p.dstAddr = &net.TCPAddr{IP: dstIP, Port: dstPort}
	}

	return nil
}
