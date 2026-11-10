package diag

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsAnswer struct {
	Addresses []netip.Addr
	Answered  bool
	NXDomain  bool
}

var dnsQueryID atomic.Uint32

func checkSTUN(ctx context.Context, physical interfaceInfo, config Config) []uint16 {
	if len(config.STUNServers) == 0 {
		return nil
	}
	conn, err := listenPacketBound(ctx, physical)
	if err != nil {
		return nil
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	type pendingRequest struct {
		server int
		addr   *net.UDPAddr
		data   []byte
	}
	requests := make([]pendingRequest, 0, len(config.STUNServers))
	for i, endpoint := range config.STUNServers {
		host, port, err := parseEndpoint(endpoint, 3478)
		if err != nil {
			continue
		}
		resolveCtx, cancel := context.WithTimeout(ctx, config.DNSTimeout)
		ip, err := resolveHost(resolveCtx, host, physical, config)
		cancel()
		if err != nil {
			continue
		}
		request, err := makeSTUNRequest()
		if err != nil {
			continue
		}
		requests = append(requests, pendingRequest{i, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(port)}, request})
	}
	if len(requests) == 0 {
		return nil
	}
	answers := make(map[int]uint16, len(requests))
	for attempt := 0; attempt < 2; attempt++ {
		pending := make(map[string]pendingRequest)
		for _, request := range requests {
			if _, answered := answers[request.server]; answered {
				continue
			}
			if attempt == 1 {
				data, err := makeSTUNRequest()
				if err != nil {
					continue
				}
				request.data = data
			}
			if _, err := conn.WriteTo(request.data, request.addr); err == nil {
				pending[string(request.data[8:20])] = request
			}
		}
		if len(pending) == 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(config.STUNTimeout))
		for len(pending) > 0 && ctx.Err() == nil {
			buffer := make([]byte, 2048)
			count, _, err := conn.ReadFrom(buffer)
			if err != nil {
				break
			}
			packet := buffer[:count]
			if len(packet) < 20 {
				continue
			}
			key := string(packet[8:20])
			request, ok := pending[key]
			if !ok {
				continue
			}
			if mapped, ok := parseSTUNResponse(request.data, packet); ok {
				answers[request.server] = mapped.Port
				delete(pending, key)
			}
		}
	}
	ports := make([]uint16, 0, len(answers))
	for _, request := range requests {
		if port, ok := answers[request.server]; ok {
			ports = append(ports, port)
		}
	}
	return ports
}

type stunMapping struct {
	Address netip.Addr
	Port    uint16
}

func makeSTUNRequest() ([]byte, error) {
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], 0x2112A442)
	if _, err := rand.Read(request[8:20]); err != nil {
		return nil, err
	}
	return request, nil
}

func parseSTUNResponse(request, response []byte) (stunMapping, bool) {
	if len(request) < 20 || len(response) < 20 || binary.BigEndian.Uint16(response[:2]) != 0x0101 ||
		binary.BigEndian.Uint32(response[4:8]) != 0x2112A442 || !equalBytes(request[8:20], response[8:20]) {
		return stunMapping{}, false
	}
	messageLen := int(binary.BigEndian.Uint16(response[2:4]))
	if messageLen > len(response)-20 {
		return stunMapping{}, false
	}
	for offset := 20; offset+4 <= 20+messageLen; {
		attribute := binary.BigEndian.Uint16(response[offset : offset+2])
		length := int(binary.BigEndian.Uint16(response[offset+2 : offset+4]))
		start, end := offset+4, offset+4+length
		if end > 20+messageLen {
			return stunMapping{}, false
		}
		if attribute == 0x0020 && length >= 4 {
			value := response[start:end]
			family := value[1]
			port := binary.BigEndian.Uint16(value[2:4]) ^ 0x2112
			switch family {
			case 1:
				if length != 8 {
					return stunMapping{}, false
				}
				cookie := []byte{0x21, 0x12, 0xa4, 0x42}
				var raw [4]byte
				for i := range raw {
					raw[i] = value[4+i] ^ cookie[i]
				}
				return stunMapping{Address: netip.AddrFrom4(raw), Port: port}, true
			case 2:
				if length != 20 {
					return stunMapping{}, false
				}
				mask := append([]byte{0x21, 0x12, 0xa4, 0x42}, request[8:20]...)
				var raw [16]byte
				for i := range raw {
					raw[i] = value[4+i] ^ mask[i]
				}
				return stunMapping{Address: netip.AddrFrom16(raw), Port: port}, true
			default:
				return stunMapping{}, false
			}
		}
		offset = start + ((length + 3) &^ 3)
	}
	return stunMapping{}, false
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}

func checkDNS(ctx context.Context, physical interfaceInfo, config Config) (map[string]dnsAnswer, map[string]dnsAnswer) {
	local := make(map[string]dnsAnswer, len(config.DNSNames))
	doh := make(map[string]dnsAnswer, len(config.DNSNames))
	if len(config.DNSNames) == 0 {
		return local, doh
	}
	type localResult struct {
		name   string
		answer dnsAnswer
	}
	localResults := make(chan localResult, len(config.DNSNames))
	var wait sync.WaitGroup
	for _, name := range config.DNSNames {
		wait.Add(1)
		go func(name string) {
			defer wait.Done()
			queryCtx, cancel := context.WithTimeout(ctx, config.DNSTimeout)
			defer cancel()
			localResults <- localResult{name, localDNSAnswer(queryCtx, name, physical)}
		}(name)
	}
	wait.Wait()
	close(localResults)
	for item := range localResults {
		local[strings.ToLower(item.name)] = item.answer
	}
	if len(config.DoHResolvers) == 0 {
		return local, doh
	}
	type dohResult struct {
		index  int
		answer dnsAnswer
	}
	probeResults := make(chan dohResult, len(config.DoHResolvers))
	name := config.DNSNames[0]
	for i, resolver := range config.DoHResolvers {
		go func(i int, resolver string) {
			queryCtx, cancel := context.WithTimeout(ctx, config.DoHTimeout)
			defer cancel()
			answer, err := dohDNSAnswer(queryCtx, resolver, name, physical)
			if err != nil {
				answer = dnsAnswer{}
			}
			probeResults <- dohResult{i, answer}
		}(i, resolver)
	}
	probes := make([]dnsAnswer, len(config.DoHResolvers))
	for range config.DoHResolvers {
		select {
		case item := <-probeResults:
			probes[item.index] = item.answer
		case <-ctx.Done():
			return local, doh
		}
	}
	selected := -1
	for i, answer := range probes {
		if answer.Answered {
			selected = i
			break
		}
	}
	if selected < 0 {
		// Public DoH resolvers are themselves blocked on many networks. With the VPN up the tunnel is the trusted path.
		return local, tunnelDNSAnswers(ctx, config)
	}
	doh[strings.ToLower(name)] = probes[selected]
	resolver := config.DoHResolvers[selected]
	dohResults := make(chan localResult, len(config.DNSNames)-1)
	for _, name := range config.DNSNames[1:] {
		wait.Add(1)
		go func(name string) {
			defer wait.Done()
			queryCtx, cancel := context.WithTimeout(ctx, config.DoHTimeout)
			defer cancel()
			answer, err := dohDNSAnswer(queryCtx, resolver, name, physical)
			if err != nil {
				answer = dnsAnswer{}
			}
			dohResults <- localResult{name, answer}
		}(name)
	}
	wait.Wait()
	close(dohResults)
	for item := range dohResults {
		doh[strings.ToLower(item.name)] = item.answer
	}
	return local, doh
}

// tunnelDNSAnswers asks public resolvers from ordinary sockets: with the VPN up they leave through the tunnel.
// Without the VPN there is no trusted path here, and the check stays "unknown".
func tunnelDNSAnswers(ctx context.Context, config Config) map[string]dnsAnswer {
	trusted := make(map[string]dnsAnswer, len(config.DNSNames))
	if config.Tunnel == nil || !config.Tunnel() {
		return trusted
	}
	type result struct {
		name   string
		answer dnsAnswer
	}
	results := make(chan result, len(config.DNSNames))
	for _, name := range config.DNSNames {
		go func(name string) {
			query, id, err := makeDNSQuery(name)
			if err != nil {
				results <- result{name, dnsAnswer{}}
				return
			}
			for _, server := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
				queryCtx, cancel := context.WithTimeout(ctx, config.DNSTimeout)
				conn, err := (&net.Dialer{}).DialContext(queryCtx, "udp", server)
				if err == nil {
					deadline, _ := queryCtx.Deadline()
					_ = conn.SetDeadline(deadline)
					buffer := make([]byte, 1500)
					if _, err = conn.Write(query); err == nil {
						var n int
						if n, err = conn.Read(buffer); err == nil {
							if answer, parseErr := parseDNSAnswer(buffer[:n], id); parseErr == nil && answer.Answered {
								_ = conn.Close()
								cancel()
								results <- result{name, answer}
								return
							}
						}
					}
					_ = conn.Close()
				}
				cancel()
			}
			results <- result{name, dnsAnswer{}}
		}(name)
	}
	for range config.DNSNames {
		if item := <-results; item.answer.Answered {
			trusted[strings.ToLower(item.name)] = item.answer
		}
	}
	return trusted
}

func localDNSAnswer(ctx context.Context, name string, physical interfaceInfo) dnsAnswer {
	if len(physical.DNS) == 0 {
		return dnsAnswer{}
	}
	query, id, err := makeDNSQuery(name)
	if err != nil {
		return dnsAnswer{}
	}
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	answers := make(chan dnsAnswer, len(physical.DNS))
	for _, server := range physical.DNS {
		go func(server netip.Addr) {
			response, err := dnsExchange(queryCtx, server, query, physical)
			if err == nil {
				var answer dnsAnswer
				answer, err = parseDNSAnswer(response, id)
				if err == nil && answer.Answered {
					answers <- answer
					return
				}
			}
			answers <- dnsAnswer{}
		}(server)
	}
	for range physical.DNS {
		select {
		case answer := <-answers:
			if answer.Answered {
				return answer
			}
		case <-ctx.Done():
			return dnsAnswer{}
		}
	}
	return dnsAnswer{}
}

func dnsReplacementCounts(local, doh map[string]dnsAnswer) (checked, replaced int) {
	repeated := make(map[string]bool)
	for name, answer := range local {
		if len(answer.Addresses) != 1 {
			continue
		}
		for other, otherAnswer := range local {
			if name != other && len(otherAnswer.Addresses) == 1 && answer.Addresses[0] == otherAnswer.Addresses[0] {
				repeated[name] = true
				break
			}
		}
	}
	for name, trusted := range doh {
		if len(trusted.Addresses) == 0 {
			continue
		}
		answer := local[name]
		if !answer.Answered {
			continue
		}
		checked++
		if answer.NXDomain || len(answer.Addresses) == 0 || hasBogon(answer.Addresses) || repeated[name] {
			replaced++
		}
	}
	return checked, replaced
}

var bogonPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func hasBogon(addresses []netip.Addr) bool {
	for _, address := range addresses {
		if !address.Is4() {
			continue
		}
		for _, prefix := range bogonPrefixes {
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func dnsVerdict(local, doh map[string]dnsAnswer, checked, replaced int) string {
	if checked == 0 || replaced == 0 && len(doh) == 0 {
		return "unknown"
	}
	if replaced > 0 {
		return "replaced"
	}
	return "ok"
}

func makeDNSQuery(name string) ([]byte, uint16, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".") + "."
	questionName, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, 0, err
	}
	id := uint16(dnsQueryID.Add(1))
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := builder.Question(dnsmessage.Question{Name: questionName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	query, err := builder.Finish()
	return query, id, err
}

func parseDNSAnswer(message []byte, id uint16) (dnsAnswer, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil {
		return dnsAnswer{}, err
	}
	if header.ID != id || !header.Response {
		return dnsAnswer{}, errors.New("DNS response mismatch")
	}
	answer := dnsAnswer{NXDomain: header.RCode == dnsmessage.RCodeNameError}
	if header.RCode != dnsmessage.RCodeSuccess && !answer.NXDomain {
		return answer, nil
	}
	if err := parser.SkipAllQuestions(); err != nil && !errors.Is(err, dnsmessage.ErrSectionDone) {
		return dnsAnswer{}, err
	}
	resources, err := parser.AllAnswers()
	if err != nil {
		return dnsAnswer{}, err
	}
	answer.Answered = true
	for _, resource := range resources {
		if value, ok := resource.Body.(*dnsmessage.AResource); ok {
			answer.Addresses = append(answer.Addresses, netip.AddrFrom4(value.A))
		}
	}
	return answer, nil
}

func dohDNSAnswer(ctx context.Context, endpoint, name string, physical interfaceInfo) (dnsAnswer, error) {
	query, id, err := makeDNSQuery(name)
	if err != nil {
		return dnsAnswer{}, err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
		return dnsAnswer{}, errors.New("invalid DoH endpoint")
	}
	values := parsed.Query()
	values.Set("dns", base64.RawURLEncoding.EncodeToString(query))
	parsed.RawQuery = values.Encode()
	response, err := dohRequest(ctx, parsed.String(), physical)
	if err != nil {
		return dnsAnswer{}, err
	}
	return parseDNSAnswer(response, id)
}

func checkForeign(ctx context.Context, physical interfaceInfo, config Config) (total, open int) {
	total = len(config.ForeignHosts)
	if total == 0 {
		return total, 0
	}
	results := make(chan bool, total)
	for _, host := range config.ForeignHosts {
		go func(host string) {
			probeCtx, cancel := context.WithTimeout(ctx, config.ForeignTimeout)
			defer cancel()
			results <- tlsProbe(probeCtx, host, physical, config)
		}(host)
	}
	for range config.ForeignHosts {
		select {
		case ok := <-results:
			if ok {
				open++
			}
		case <-ctx.Done():
			return total, open
		}
	}
	return total, open
}

func foreignVerdictMessage(total, open int) string {
	return fmt.Sprintf("total=%d open=%d", total, open)
}
