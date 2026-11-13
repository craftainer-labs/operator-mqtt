package dynsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/packets"
)

const (
	fakeUser     = "admin"
	fakePassword = "s3cret"
)

// behavior says how the fake broker misbehaves. The zero value is a broker
// that accepts the admin, the subscription and every publish, and lets the
// test's handler answer commands.
type behavior struct {
	connack byte // CONNACK reason code
	suback  byte // SUBACK reason code
	puback  byte // PUBACK reason code

	silentConnect      bool // read CONNECT, answer nothing
	closeBeforeConnack bool // read CONNECT, close
	closeAfterConnack  bool // answer CONNECT, close
	mute               bool // read PUBLISH, answer nothing at all
	closeOnPublish     bool // read PUBLISH, close without a PUBACK
	closeAfterPuback   bool // PUBACK, then close
	noise              bool // before each answer, send two messages that are not answers

	// sans are the names of the server certificate; default localhost and
	// 127.0.0.1.
	sans []string
}

// handler answers one command with the elements of a response, or none.
type handler func(cmd map[string]any) []map[string]any

// fakeBroker is an in-process MQTT v5 broker over TLS that speaks just enough
// for the client: CONNECT, SUBSCRIBE, PUBLISH (QoS 0 and 1), PINGREQ and
// DISCONNECT, and answers dynsec commands through a handler.
type fakeBroker struct {
	t      *testing.T
	b      behavior
	ln     net.Listener
	CAPEM  []byte
	Addr   string
	handle handler

	mu       sync.Mutex
	commands []map[string]any
	closed   bool
	wg       sync.WaitGroup
}

func newFakeBroker(t *testing.T, b behavior, h handler) *fakeBroker {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dynsec test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	sans := b.sans
	if sans == nil {
		sans = []string{"localhost", "127.0.0.1"}
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "broker"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			leafTmpl.IPAddresses = append(leafTmpl.IPAddresses, ip)
		} else {
			leafTmpl.DNSNames = append(leafTmpl.DNSNames, s)
		}
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBroker{
		t:      t,
		b:      b,
		CAPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		Addr:   raw.Addr().String(),
		handle: h,
	}
	fb.ln = tls.NewListener(raw, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
	})
	fb.wg.Add(1)
	go fb.accept()
	t.Cleanup(fb.Close)
	return fb
}

func (fb *fakeBroker) Close() {
	fb.mu.Lock()
	already := fb.closed
	fb.closed = true
	fb.mu.Unlock()
	if !already {
		_ = fb.ln.Close()
	}
	fb.wg.Wait()
}

// Commands returns the commands received so far, in order.
func (fb *fakeBroker) Commands() []map[string]any {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return append([]map[string]any(nil), fb.commands...)
}

func (fb *fakeBroker) accept() {
	defer fb.wg.Done()
	for {
		c, err := fb.ln.Accept()
		if err != nil {
			return
		}
		fb.wg.Add(1)
		go fb.serve(c)
	}
}

func write(c net.Conn, cp *packets.ControlPacket) {
	_, _ = cp.WriteTo(c)
}

func (fb *fakeBroker) serve(c net.Conn) {
	defer fb.wg.Done()
	defer c.Close()
	for {
		cp, err := packets.ReadPacket(c)
		if err != nil {
			return
		}
		switch p := cp.Content.(type) {
		case *packets.Connect:
			if !fb.connect(c, p) {
				return
			}
		case *packets.Subscribe:
			ack := packets.NewControlPacket(packets.SUBACK)
			ack.Content = &packets.Suback{PacketID: p.PacketID, Reasons: []byte{fb.b.suback}}
			write(c, ack)
		case *packets.Publish:
			if !fb.publish(c, p) {
				return
			}
		case *packets.Pingreq:
			write(c, packets.NewControlPacket(packets.PINGRESP))
		case *packets.Disconnect:
			return
		}
	}
}

// connect answers a CONNECT; false ends the connection.
func (fb *fakeBroker) connect(c net.Conn, p *packets.Connect) bool {
	switch {
	case fb.b.silentConnect:
		return true
	case fb.b.closeBeforeConnack:
		return false
	}
	code := fb.b.connack
	if string(p.Password) != fakePassword || p.Username != fakeUser {
		code = 0x86
	}
	ack := packets.NewControlPacket(packets.CONNACK)
	ack.Content = &packets.Connack{ReasonCode: code, Properties: &packets.Properties{}}
	write(c, ack)
	return code == 0 && !fb.b.closeAfterConnack
}

// publish handles a PUBLISH from the client; false ends the connection.
func (fb *fakeBroker) publish(c net.Conn, p *packets.Publish) bool {
	switch {
	case fb.b.mute:
		return true
	case fb.b.closeOnPublish:
		return false
	}
	if p.QoS == 1 {
		ack := packets.NewControlPacket(packets.PUBACK)
		ack.Content = &packets.Puback{PacketID: p.PacketID, ReasonCode: fb.b.puback}
		write(c, ack)
	}
	if fb.b.closeAfterPuback {
		return false
	}
	if fb.b.puback >= 0x80 {
		return true
	}
	var env struct {
		Commands []map[string]any `json:"commands"`
	}
	if err := json.Unmarshal(p.Payload, &env); err != nil {
		fb.t.Errorf("fake broker: unreadable command %q: %v", p.Payload, err)
		return true
	}
	for _, cmd := range env.Commands {
		fb.mu.Lock()
		fb.commands = append(fb.commands, cmd)
		fb.mu.Unlock()
		if fb.handle == nil {
			continue
		}
		responses := fb.handle(cmd)
		if responses == nil {
			continue
		}
		if fb.b.noise {
			fb.send(c, "other/topic", []byte("x"))
			fb.send(c, DefaultControlTopic+"/response", []byte("not json"))
		}
		payload, _ := json.Marshal(map[string]any{"responses": responses})
		fb.send(c, DefaultControlTopic+"/response", payload)
	}
	return true
}

// send publishes a message to the client with QoS 0.
func (fb *fakeBroker) send(c net.Conn, topic string, payload []byte) {
	pub := packets.NewControlPacket(packets.PUBLISH)
	pub.Content = &packets.Publish{Topic: topic, Payload: payload, Properties: &packets.Properties{}}
	write(c, pub)
}

// okReply answers a command the way the plugin does on success: the command, the
// data when there is some, and the correlation data of the request.
func okReply(cmd map[string]any, data map[string]any) []map[string]any {
	r := map[string]any{"command": cmd["command"], "correlationData": cmd["correlationData"]}
	if data != nil {
		r["data"] = data
	}
	return []map[string]any{r}
}

// failReply answers a command with the plugin's error text.
func failReply(cmd map[string]any, msg string) []map[string]any {
	return []map[string]any{{"command": cmd["command"], "error": msg, "correlationData": cmd["correlationData"]}}
}

// config returns a Config that reaches the fake broker as its admin.
func (fb *fakeBroker) config() Config {
	return Config{Address: fb.Addr, CA: fb.CAPEM, Username: fakeUser, Password: fakePassword, Timeout: 2 * time.Second}
}
