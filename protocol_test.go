package proxyproto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	goodAddr = "127.0.0.1"
	badAddr  = "127.0.0.2"
	errAddr  = "9999.0.0.2"
	host     = "localhost"
	country  = "USA"
	company  = "VXControl Co"
)

var (
	checkAddr string
)

// GenX509KeyPair generates the TLS keypair for the server
func GenX509KeyPair() (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:   host,
			Country:      []string{country},
			Organization: []string{company},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1), // Valid for one day
		SubjectKeyId:          []byte{113, 117, 105, 99, 107, 115, 101, 114, 118, 101},
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}

func TestMain(m *testing.M) {
	log.SetLevel(log.InfoLevel)
	os.Exit(m.Run())
}

func TestPassthrough(t *testing.T) {
	var wg sync.WaitGroup
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}
	EnableDebugging = true

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestPassthroughTLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:  l,
		TLSConfig: sconfig,
	}
	EnableDebugging = true

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := tls.Dial("tcp", pl.Addr().String(), cconfig)
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestPassthroughDoubleSendTLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:  l,
		TLSConfig: sconfig,
	}
	EnableDebugging = true

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := tls.Dial("tcp", pl.Addr().String(), cconfig)
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

		conn.Write([]byte("ping"))
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestTimeout(t *testing.T) {
	var wg sync.WaitGroup
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	clientWriteDelay := 200 * time.Millisecond
	proxyHeaderTimeout := 50 * time.Millisecond
	pl := &Listener{Listener: l, ProxyHeaderTimeout: proxyHeaderTimeout}

	wg.Add(1)
	go func() {
		defer wg.Done()
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
		t.Fatalf("RemoteAddr() took longer than the specified timeout: %v < %v",
			proxyHeaderTimeout, remoteAddrDuration)
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestTimeoutTLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	clientWriteDelay := 200 * time.Millisecond
	proxyHeaderTimeout := 50 * time.Millisecond
	pl := &Listener{
		Listener:           l,
		TLSConfig:          sconfig,
		ProxyHeaderTimeout: proxyHeaderTimeout,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := tls.Dial("tcp", pl.Addr().String(), cconfig)
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
		t.Fatalf("RemoteAddr() took longer than the specified timeout: %v < %v",
			proxyHeaderTimeout, remoteAddrDuration)
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_ipv4(t *testing.T) {
	var wg sync.WaitGroup
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_ipv4TLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:  l,
		TLSConfig: sconfig,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n"
		conn.Write([]byte(header))

		// Upgrade TCP connection to TLS
		conn = tls.Client(conn, cconfig)

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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_ipv6(t *testing.T) {
	var wg sync.WaitGroup
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_ipv6TLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:  l,
		TLSConfig: sconfig,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP6 ffff::ffff ffff::ffff 1000 2000\r\n"
		conn.Write([]byte(header))

		// Upgrade TCP connection to TLS
		conn = tls.Client(conn, cconfig)

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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_BadHeader(t *testing.T) {
	var wg sync.WaitGroup
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_BadHeaderTLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:  l,
		TLSConfig: sconfig,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP4 what 127.0.0.1 1000 2000\r\n"
		conn.Write([]byte(header))

		// Upgrade TCP connection to TLS
		conn = tls.Client(conn, cconfig)

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
	// Wait for all Data fetches to complete.
	wg.Wait()
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
	var wg sync.WaitGroup
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

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_ipv4_checkfuncTLS(t *testing.T) {
	checkAddr = goodAddr
	testParse_ipv4_checkfuncTLS(t)
	checkAddr = badAddr
	testParse_ipv4_checkfuncTLS(t)
	checkAddr = errAddr
	testParse_ipv4_checkfuncTLS(t)
}

func testParse_ipv4_checkfuncTLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

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

	pl := &Listener{
		Listener:    l,
		TLSConfig:   sconfig,
		SourceCheck: checkFunc,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := "PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n"
		conn.Write([]byte(header))

		// Upgrade TCP connection to TLS
		conn = tls.Client(conn, cconfig)

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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_v2_ipv4(t *testing.T) {
	var wg sync.WaitGroup
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_v2_ipv4TLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:  l,
		TLSConfig: sconfig,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
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

		// Upgrade TCP connection to TLS
		conn = tls.Client(conn, cconfig)

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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_v2_ipv6(t *testing.T) {
	var wg sync.WaitGroup
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	wg.Add(1)
	go func() {
		defer wg.Done()
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
	// Wait for all Data fetches to complete.
	wg.Wait()
}

func TestParse_v2_ipv6TLS(t *testing.T) {
	var wg sync.WaitGroup
	cert, err := GenX509KeyPair()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sconfig := &tls.Config{}
	sconfig.Certificates = make([]tls.Certificate, 1)
	sconfig.Certificates[0] = cert

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:  l,
		TLSConfig: sconfig,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		cconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
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

		// Upgrade TCP connection to TLS
		conn = tls.Client(conn, cconfig)

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
	// Wait for all Data fetches to complete.
	wg.Wait()
}
