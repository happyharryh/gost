package gost

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
	glob "github.com/gobwas/glob"
	"github.com/golang/groupcache/lru"
)

// Matcher is a generic pattern matcher,
// it gives the match result of the given pattern for specific v.
type Matcher interface {
	Match(v string) bool
	String() string
}

// NewMatcher creates a Matcher for the given pattern.
// The acutal Matcher depends on the pattern:
// IP Matcher if pattern is a valid IP address.
// CIDR Matcher if pattern is a valid CIDR address.
// Domain Matcher if both of the above are not.
func NewMatcher(pattern string) Matcher {
	if pattern == "" {
		return nil
	}
	if ip := net.ParseIP(pattern); ip != nil {
		return IPMatcher(ip)
	}
	if _, inet, err := net.ParseCIDR(pattern); err == nil {
		return CIDRMatcher(inet)
	}
	return DomainMatcher(pattern)
}

type ipMatcher struct {
	ip net.IP
}

// IPMatcher creates a Matcher for a specific IP address.
func IPMatcher(ip net.IP) Matcher {
	return &ipMatcher{
		ip: ip,
	}
}

func (m *ipMatcher) Match(ip string) bool {
	if m == nil {
		return false
	}
	return m.ip.Equal(net.ParseIP(ip))
}

func (m *ipMatcher) String() string {
	return "ip " + m.ip.String()
}

type cidrMatcher struct {
	ipNet *net.IPNet
}

// CIDRMatcher creates a Matcher for a specific CIDR notation IP address.
func CIDRMatcher(inet *net.IPNet) Matcher {
	return &cidrMatcher{
		ipNet: inet,
	}
}

func (m *cidrMatcher) Match(ip string) bool {
	if m == nil || m.ipNet == nil {
		return false
	}
	return m.ipNet.Contains(net.ParseIP(ip))
}

func (m *cidrMatcher) String() string {
	return "cidr " + m.ipNet.String()
}

type domainMatcher struct {
	pattern string
	glob    glob.Glob
}

// DomainMatcher creates a Matcher for a specific domain pattern,
// the pattern can be a plain domain such as 'example.com',
// a wildcard such as '*.exmaple.com' or a special wildcard '.example.com'.
func DomainMatcher(pattern string) Matcher {
	p := pattern
	if strings.HasPrefix(pattern, ".") {
		p = pattern[1:] // trim the prefix '.'
		pattern = "*" + p
	}
	return &domainMatcher{
		pattern: p,
		glob:    glob.MustCompile(pattern),
	}
}

func (m *domainMatcher) Match(domain string) bool {
	if m == nil || m.glob == nil {
		return false
	}

	if domain == m.pattern {
		return true
	}
	return m.glob.Match(domain)
}

func (m *domainMatcher) String() string {
	return "domain " + m.pattern
}

// Bypass is a filter for address (IP or domain).
// It contains a list of matchers.
type Bypass struct {
	matchers []Matcher
	period   time.Duration // the period for live reloading
	reversed bool
	resolve  bool
	stopped  chan struct{}
	mux      sync.RWMutex
	cache    *lru.Cache
	cacheMux sync.Mutex
}

// NewBypass creates and initializes a new Bypass using matchers as its match rules.
// The rules will be reversed if the reversed is true.
func NewBypass(reversed bool, matchers ...Matcher) *Bypass {
	return &Bypass{
		matchers: matchers,
		reversed: reversed,
		stopped:  make(chan struct{}),
		cache:    lru.New(1 << 10),
	}
}

// NewBypassPatterns creates and initializes a new Bypass using matcher patterns as its match rules.
// The rules will be reversed if the reverse is true.
func NewBypassPatterns(reversed bool, patterns ...string) *Bypass {
	var matchers []Matcher
	for _, pattern := range patterns {
		if m := NewMatcher(pattern); m != nil {
			matchers = append(matchers, m)
		}
	}
	bp := NewBypass(reversed)
	bp.AddMatchers(matchers...)
	return bp
}

// Contains reports whether the bypass includes addr.
func (bp *Bypass) Contains(addr string) bool {
	if bp == nil || addr == "" {
		return false
	}

	// try to strip the port
	if host, port, _ := net.SplitHostPort(addr); host != "" && port != "" {
		if p, _ := strconv.Atoi(port); p > 0 { // port is valid
			addr = host
		}
	}

	bp.mux.RLock()
	defer bp.mux.RUnlock()

	if len(bp.matchers) == 0 {
		return false
	}

	bp.cacheMux.Lock()
	result, ok := bp.cache.Get(addr)
	bp.cacheMux.Unlock()
	if ok {
		return result.(bool)
	}

	isIP := net.ParseIP(addr) != nil
	var resolvedAddr string
	var matched, resolveFailed bool
	for _, matcher := range bp.matchers {
		if matcher == nil {
			continue
		}
		if _, ok := matcher.(*domainMatcher); ok || isIP {
			matched = matcher.Match(addr)
		} else if bp.resolve && !resolveFailed {
			if resolvedAddr == "" {
				ipAddr, err := net.ResolveIPAddr("ip", addr)
				if err != nil {
					resolveFailed = true
					log.Logf("[bypass] resolve %s : %s", addr, err)
					continue
				}
				resolvedAddr = ipAddr.String()
			}
			matched = matcher.Match(resolvedAddr)
		}
		if matched {
			break
		}
	}
	result = matched != bp.reversed

	if matched || !resolveFailed {
		bp.cacheMux.Lock()
		bp.cache.Add(addr, result)
		bp.cacheMux.Unlock()
	}
	return result.(bool)
}

// AddMatchers appends matchers to the bypass matcher list.
func (bp *Bypass) AddMatchers(matchers ...Matcher) {
	bp.mux.Lock()
	defer bp.mux.Unlock()

	bp.matchers = append(bp.matchers, matchers...)
}

// Matchers return the bypass matcher list.
func (bp *Bypass) Matchers() []Matcher {
	bp.mux.RLock()
	defer bp.mux.RUnlock()

	return bp.matchers
}

// Reversed reports whether the rules of the bypass are reversed.
func (bp *Bypass) Reversed() bool {
	bp.mux.RLock()
	defer bp.mux.RUnlock()

	return bp.reversed
}

// Resolve reports whether the IP/CIDR rules match resolved domains.
func (bp *Bypass) Resolve() bool {
	bp.mux.RLock()
	defer bp.mux.RUnlock()

	return bp.resolve
}

// Reload parses config from r, then live reloads the bypass.
func (bp *Bypass) Reload(r io.Reader) error {
	var matchers []Matcher
	var period time.Duration
	var reversed, resolve bool

	if r == nil || bp.Stopped() {
		return nil
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		ss := splitLine(line)
		if len(ss) == 0 {
			continue
		}
		switch ss[0] {
		case "reload": // reload option
			if len(ss) > 1 {
				period, _ = time.ParseDuration(ss[1])
			}
		case "reverse": // reverse option
			if len(ss) > 1 {
				reversed, _ = strconv.ParseBool(ss[1])
			}
		case "resolve": // resolve option
			if len(ss) > 1 {
				resolve, _ = strconv.ParseBool(ss[1])
			}
		default:
			matchers = append(matchers, NewMatcher(ss[0]))
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	bp.mux.Lock()
	defer bp.mux.Unlock()

	bp.matchers = matchers
	bp.period = period
	bp.reversed = reversed
	bp.resolve = resolve
	bp.cache.Clear()

	return nil
}

// Period returns the reload period.
func (bp *Bypass) Period() time.Duration {
	if bp.Stopped() {
		return -1
	}

	bp.mux.RLock()
	defer bp.mux.RUnlock()

	return bp.period
}

// Stop stops reloading.
func (bp *Bypass) Stop() {
	select {
	case <-bp.stopped:
	default:
		close(bp.stopped)
	}
}

// Stopped checks whether the reloader is stopped.
func (bp *Bypass) Stopped() bool {
	select {
	case <-bp.stopped:
		return true
	default:
		return false
	}
}

func (bp *Bypass) String() string {
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "reversed: %v\n", bp.Reversed())
	fmt.Fprintf(b, "resolve: %v\n", bp.Resolve())
	fmt.Fprintf(b, "reload: %v\n", bp.Period())
	for _, m := range bp.Matchers() {
		b.WriteString(m.String())
		b.WriteByte('\n')
	}
	return b.String()
}
