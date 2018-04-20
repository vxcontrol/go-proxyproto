package proxyproto

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
)

const (
	goodAddr = "127.0.0.1"
	badAddr  = "127.0.0.2"
	errAddr  = "9999.0.0.2"
)

var (
	checkAddr string
)

func TestPassthrough(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	clientWriteDelay := 200 * time.Millisecond
	proxyHeaderTimeout := 50 * time.Millisecond
	pl := &Listener{Listener: l, ProxyHeaderTimeout: proxyHeaderTimeout}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Do not send data for a while
		time.Sleep(clientWriteDelay)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	// Check the remote addr is the original 127.0.0.1
	remoteAddrStartTime := time.Now()
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "127.0.0.1" {
		t.Fatalf("bad: %v", addr)
	}
	remoteAddrDuration := time.Since(remoteAddrStartTime)

	// Check RemoteAddr() call did timeout
	if remoteAddrDuration >= clientWriteDelay {
		t.Fatalf("RemoteAddr() took longer than the specified timeout: %v < %v", proxyHeaderTimeout, remoteAddrDuration)
	}

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestParse_ipv4(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n"
		conn.Write([]byte(header))

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "10.1.1.1" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}
}

func TestParse_ipv6(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP6 ffff::ffff ffff::ffff 1000 2000\r\n"
		conn.Write([]byte(header))

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "ffff::ffff" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}
}

func TestParse_BadHeader(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP4 what 127.0.0.1 1000 2000\r\n"
		conn.Write([]byte(header))

		conn.Write([]byte("ping"))

		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err == nil {
			t.Fatalf("err: %v", err)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	// Check the remote addr, should be the local addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "127.0.0.1" {
		t.Fatalf("bad: %v", addr)
	}

	// Read should fail
	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err == nil {
		t.Fatalf("err: %v", err)
	}
}

func TestParse_ipv4_checkfunc(t *testing.T) {
	checkAddr = goodAddr
	testParse_ipv4_checkfunc(t)
	checkAddr = badAddr
	testParse_ipv4_checkfunc(t)
	checkAddr = errAddr
	testParse_ipv4_checkfunc(t)
}

func testParse_ipv4_checkfunc(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	checkFunc := func(addr net.Addr) (bool, error) {
		tcpAddr := addr.(*net.TCPAddr)
		if tcpAddr.IP.String() == checkAddr {
			return true, nil
		}
		return false, nil
	}

	pl := &Listener{Listener: l, SourceCheck: checkFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n"
		conn.Write([]byte(header))

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		if checkAddr == badAddr {
			return
		}
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	switch checkAddr {
	case goodAddr:
		if addr.IP.String() != "10.1.1.1" {
			t.Fatalf("bad: %v", addr)
		}
		if addr.Port != 1000 {
			t.Fatalf("bad: %v", addr)
		}
	case badAddr:
		if addr.IP.String() != "127.0.0.1" {
			t.Fatalf("bad: %v", addr)
		}
		if addr.Port == 1000 {
			t.Fatalf("bad: %v", addr)
		}
	}
}

func TestParse_v2_ipv4(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		ipaddrSrc := net.ParseIP("10.1.1.1")
		portSrc := uint16(80)
		ipaddrDst := net.ParseIP("192.55.100.1")
		portDst := uint16(81)

		header := []byte{}
		data := []byte{}
		tmp := make([]byte, 2)
		header = append(header, prefixV2...)
		header = append(header, commandProxy)
		header = append(header, addressFamilyInet|transportProtoStream)

		binary.BigEndian.PutUint16(tmp, portSrc)
		data = append(data, ipaddrSrc[12:16]...)

		binary.BigEndian.PutUint16(tmp, portSrc)
		data = append(data, tmp[0:2]...)

		data = append(data, ipaddrDst[12:16]...)
		binary.BigEndian.PutUint16(tmp, portDst)
		data = append(data, tmp[0:2]...)

		binary.BigEndian.PutUint16(tmp, uint16(len(data)))
		header = append(header, tmp...)

		conn.Write([]byte(header))
		conn.Write([]byte(data))

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v - %v", recv, string(recv))
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v - %v", recv, string(recv))
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "10.1.1.1" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 80 {
		t.Fatalf("bad: %v", addr)
	}
}

func TestMain(m *testing.M) {
	log.SetLevel(log.DebugLevel)
	os.Exit(m.Run())
}

func TestParse_v2_ipv6(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		ipaddrSrc := net.ParseIP("ffff::ffff")
		portSrc := uint16(80)
		ipaddrDst := net.ParseIP("ffff::ffff")
		portDst := uint16(81)

		header := []byte{}
		data := []byte{}
		tmp := make([]byte, 2)
		header = append(header, prefixV2...)
		header = append(header, commandProxy)
		header = append(header, addressFamilyInet6|transportProtoStream)

		binary.BigEndian.PutUint16(tmp, portSrc)
		data = append(data, ipaddrSrc...)

		binary.BigEndian.PutUint16(tmp, portSrc)
		data = append(data, tmp[0:2]...)

		data = append(data, ipaddrDst...)
		binary.BigEndian.PutUint16(tmp, portDst)
		data = append(data, tmp[0:2]...)

		data = append(data, []byte("some-extra-data-what-should-be-discarded\x01\x01")...)

		binary.BigEndian.PutUint16(tmp, uint16(len(data)))
		header = append(header, tmp...)

		conn.Write([]byte(header))
		conn.Write([]byte(data))

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v - %v", recv, string(recv))
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v - %v", recv, string(recv))
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "ffff::ffff" {
		t.Fatalf("bad: %v", addr.IP.String())
	}
	if addr.Port != 80 {
		t.Fatalf("bad: %v", addr)
	}
}
