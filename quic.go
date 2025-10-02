package gost

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/congestion"
	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/apernet/quic-go"
	"github.com/go-log/log"
	"golang.org/x/crypto/blake2s"
)

type quicSession struct {
	session *quic.Conn
}

func (session *quicSession) GetConn() (*quicConn, error) {
	stream, err := session.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &quicConn{
		Stream: stream,
		laddr:  session.session.LocalAddr(),
		raddr:  session.session.RemoteAddr(),
	}, nil
}

func (session *quicSession) Close() error {
	return session.session.CloseWithError(quic.ApplicationErrorCode(0), "closed")
}

type quicTransporter struct {
	config       *QUICConfig
	sessionMutex sync.Mutex
	sessions     map[string]*quicSession
}

// QUICTransporter creates a Transporter that is used by QUIC proxy client.
func QUICTransporter(config *QUICConfig) Transporter {
	if config == nil {
		config = &QUICConfig{}
	}

	if config.ReceiveWindowConn == 0 {
		config.ReceiveWindowConn = DefaultReceiveWindowConn
	}
	if config.ReceiveWindow == 0 {
		config.ReceiveWindow = DefaultReceiveWindow
	}

	return &quicTransporter{
		config:   config,
		sessions: make(map[string]*quicSession),
	}
}

func (tr *quicTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if ok {
		conn, err = session.GetConn()
		if err != nil {
			session.Close()
			delete(tr.sessions, addr)
			ok = false
		}
	}

	if !ok {
		var udpAddr net.Addr
		udpAddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return
		}

		var pc net.PacketConn
		pc, err = net.ListenUDP("udp", nil)
		if err != nil {
			return
		}

		if tr.config != nil && tr.config.Key != nil {
			keyCapacity := len(tr.config.Key) + cipherSuffixLen
			pc = &quicCipherConn{
				PacketConn: pc,
				keyR:       append(make([]byte, 0, keyCapacity), tr.config.Key...),
				keyW:       append(make([]byte, 0, keyCapacity), tr.config.Key...),
			}
		}

		session, err = tr.initSession(udpAddr, pc)
		if err != nil {
			pc.Close()
			return nil, err
		}

		conn, err = session.GetConn()
		if err != nil {
			session.Close()
			pc.Close()
			return nil, err
		}

		tr.sessions[addr] = session
	}
	return conn, nil
}

func (tr *quicTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *quicTransporter) initSession(addr net.Addr, conn net.PacketConn) (*quicSession, error) {
	config := tr.config
	if config == nil {
		config = &QUICConfig{}
	}
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: config.Timeout,
		MaxIdleTimeout:       config.IdleTimeout,
		KeepAlivePeriod:      config.KeepAlivePeriod,
		Versions: []quic.Version{
			quic.Version1,
			quic.Version2,
		},
		DisablePathManager: true,

		InitialStreamReceiveWindow:     config.ReceiveWindowConn,
		MaxStreamReceiveWindow:         config.ReceiveWindowConn,
		InitialConnectionReceiveWindow: config.ReceiveWindow,
		MaxConnectionReceiveWindow:     config.ReceiveWindow,
	}
	session, err := quic.DialEarly(context.Background(), conn, addr, tlsConfigQUICALPN(config.TLSConfig), quicConfig)
	if err != nil {
		log.Logf("quic dial %s: %v", addr, err)
		return nil, err
	}
	if config.SendBps > 0 {
		congestion.UseBrutal(session, config.SendBps)
	} else {
		congestion.UseBBR(session)
	}
	return &quicSession{session: session}, nil
}

func (tr *quicTransporter) Multiplex() bool {
	return true
}

// QUICConfig is the config for QUIC client and server
type QUICConfig struct {
	TLSConfig       *tls.Config
	Timeout         time.Duration
	KeepAlive       bool
	KeepAlivePeriod time.Duration
	IdleTimeout     time.Duration
	Key             []byte

	SendBps           uint64
	ReceiveWindowConn uint64
	ReceiveWindow     uint64
	MaxConnClient     int64
}

const (
	MbpsToBps                = 1024 * 1024 / 8  // Mbit/Byte
	DefaultReceiveWindowConn = 8 * 1024 * 1024  // 8MB
	DefaultReceiveWindow     = 20 * 1024 * 1024 // 20MB
	DefaultMaxConnClient     = 1024

	cipherSuffixLen = 4
)

type quicListener struct {
	ln       quic.EarlyListener
	connChan chan net.Conn
	errChan  chan error
}

// QUICListener creates a Listener for QUIC proxy server.
func QUICListener(addr string, config *QUICConfig) (Listener, error) {
	if config == nil {
		config = &QUICConfig{}
	}

	if config.ReceiveWindowConn == 0 {
		config.ReceiveWindowConn = DefaultReceiveWindowConn
	}
	if config.ReceiveWindow == 0 {
		config.ReceiveWindow = DefaultReceiveWindow
	}
	if config.MaxConnClient == 0 {
		config.MaxConnClient = DefaultMaxConnClient
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: config.Timeout,
		KeepAlivePeriod:      config.KeepAlivePeriod,
		MaxIdleTimeout:       config.IdleTimeout,
		Versions: []quic.Version{
			quic.Version1,
			quic.Version2,
		},
		DisablePathManager: true,

		InitialStreamReceiveWindow:     config.ReceiveWindowConn,
		MaxStreamReceiveWindow:         config.ReceiveWindowConn,
		InitialConnectionReceiveWindow: config.ReceiveWindow,
		MaxConnectionReceiveWindow:     config.ReceiveWindow,
		MaxIncomingStreams:             config.MaxConnClient,
	}

	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	var conn net.PacketConn

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err = correctnet.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	if config.Key != nil {
		keyCapacity := len(config.Key) + cipherSuffixLen
		conn = &quicCipherConn{
			PacketConn: conn,
			keyR:       append(make([]byte, 0, keyCapacity), config.Key...),
			keyW:       append(make([]byte, 0, keyCapacity), config.Key...),
		}
	}

	ln, err := quic.ListenEarly(conn, tlsConfigQUICALPN(tlsConfig), quicConfig)
	if err != nil {
		return nil, err
	}

	l := &quicListener{
		ln:       *ln,
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}
	go l.listenLoop(config.SendBps)

	return l, nil
}

func (l *quicListener) listenLoop(bps uint64) {
	for {
		session, err := l.ln.Accept(context.Background())
		if err != nil {
			log.Log("[quic] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		if bps > 0 {
			congestion.UseBrutal(session, bps)
		} else {
			congestion.UseBBR(session)
		}
		go l.sessionLoop(session)
	}
}

func (l *quicListener) sessionLoop(session *quic.Conn) {
	log.Logf("[quic] %s <-> %s", session.RemoteAddr(), session.LocalAddr())
	defer log.Logf("[quic] %s >-< %s", session.RemoteAddr(), session.LocalAddr())

	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			log.Log("[quic] accept stream:", err)
			session.CloseWithError(quic.ApplicationErrorCode(0), "closed")
			return
		}

		cc := &quicConn{Stream: stream, laddr: session.LocalAddr(), raddr: session.RemoteAddr()}
		select {
		case l.connChan <- cc:
		default:
			cc.Close()
			log.Logf("[quic] %s - %s: connection queue is full", session.RemoteAddr(), session.LocalAddr())
		}
	}
}

func (l *quicListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.connChan:
	case err, ok = <-l.errChan:
		if !ok {
			err = errors.New("accpet on closed listener")
		}
	}
	return
}

func (l *quicListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *quicListener) Close() error {
	return l.ln.Close()
}

type quicConn struct {
	*quic.Stream
	laddr net.Addr
	raddr net.Addr
}

func (c *quicConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *quicConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *quicConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

type quicCipherConn struct {
	net.PacketConn
	keyR, keyW []byte
}

func (conn *quicCipherConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	if n, addr, err = conn.PacketConn.ReadFrom(data); n > cipherSuffixLen {
		key := blake2s.Sum256(append(conn.keyR, data[n-cipherSuffixLen:n]...))
		for i, c := range data[:n-cipherSuffixLen] {
			data[i] = c ^ key[i%blake2s.Size]
		}
	}
	return n, addr, err
}

func (conn *quicCipherConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	if n := len(data); n > cipherSuffixLen {
		key := blake2s.Sum256(append(conn.keyW, data[n-cipherSuffixLen:n]...))
		for i, c := range data[:n-cipherSuffixLen] {
			data[i] = c ^ key[i%blake2s.Size]
		}
	}
	return conn.PacketConn.WriteTo(data, addr)
}

func tlsConfigQUICALPN(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig == nil {
		panic("quic: tlsconfig is nil")
	}
	tlsConfigQUIC := tlsConfig.Clone()
	tlsConfigQUIC.NextProtos = []string{"http/3", "quic/v1"}
	return tlsConfigQUIC
}
