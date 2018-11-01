package main

import (
	"encoding/binary"
	"fmt"
	. "github.com/miekg/dns"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var seen = map[string]time.Time{}
var lock = sync.RWMutex{}

// Remove all DNS entries older than 1 hour.
func Cleanup() {
	log.Printf("Starting cleanup. Current number of entries: %d", len(seen))
	now := time.Now()
	lock.RLock()
	for k, v := range seen {
		diff := now.Sub(v)
		if diff.Hours() > 1 {
			delete(seen, k)
		}
	}
	lock.RUnlock()
	log.Printf("Cleanup Done. Number of remaining entries: %d", len(seen))
}

// Function to regularly remove old DNS entries.
// This function never returns (TODO fix this with extra channel argument?).
func Cleaner() {
	c := time.Tick(1 * time.Hour)
	for _ = range c {
		Cleanup()
	}
}

func ParseMode(s string) int {
	if len(s) < 1 || int(s[0]) < 48 || int(s[0]) > 50 {
		return 0
	}
	return int(s[0]) - 48
}

func ParseIP(s string) net.IP {
	intval, err := strconv.ParseUint(s, 16, 32)
	var ip net.IP
	if err == nil {
		ip = make([]byte, 4)
		binary.BigEndian.PutUint32(ip, uint32(intval))
	}
	return ip
}

// Parses our custom DNS format:
//  	randstring_ip1_ip2.domain
//   OR
//      randstring_ip.domain
//   OR
//     randstring_mode_ip1_ip2.domain
//
// The IP addresses are encoded as 32 bit integers in hexadecimal representation, i.e. 7f000001 for 127.0.0.1
// Only IPv4 is supported for now... TODO
// The mode is a single digit, either 0, 1 or 2, meaning:
//     0 : reply to both A and AAAA requests
//     1 : only reply to A requests
//     2 : only reply to AAAA requests (and embed the IPv4 address inside of the IPV6 response)
func ParseEntry(entry string) (int, net.IP, net.IP) {
	parts := strings.Split(entry, "_")
	if len(parts) == 1 {
		return 0, nil, nil
	} else if len(parts) == 2 {
		// Type 2
		return 0, ParseIP(parts[1]), nil
	} else if len(parts) == 3 {
		// Type 1
		return 0, ParseIP(parts[1]), ParseIP(parts[2])
	} else {
		return ParseMode(parts[1]), ParseIP(parts[2]), ParseIP(parts[3])
	}
}

func TypeAEnabled(mode int) bool {
	return mode == 0 || mode == 1
}

func TypeAAAAEnabled(mode int) bool {
	return mode == 0 || mode == 2
}

func EmbedIPv4InIPv6(ip net.IP) net.IP {
	// http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding-2.htm
	var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	return append(v4InV6Prefix, ip[len(ip)-4:]...)
}

func HandleRequest(w ResponseWriter, req *Msg) {
	m := new(Msg)
	m.SetReply(req)

	// Always send a (possibly empty) reply
	defer w.WriteMsg(m)

	if len(m.Question) < 1 {
		log.Printf("Unsupported request, question missing")
		return
	}
	name := m.Question[0].Name

	qtype := m.Question[0].Qtype
	if qtype != TypeA && qtype != TypeAAAA {
		log.Printf("Unsupported %s request for %s", TypeToString[qtype], name)
		return
	}

	var ip net.IP
	m.Answer = make([]RR, 1)

	mode, ip1, ip2 := ParseEntry(strings.Split(name, ".")[0])
	if ip1 == nil {
		ip = net.ParseIP("1.3.3.7")
	} else if ip2 == nil {
		ip = ip1
	} else {
		lock.RLock()
		if _, ok := seen[name]; ok {
			ip = ip2
		} else {
			ip = ip1
			seen[name] = time.Now()
		}
		lock.RUnlock()
	}

	if qtype == TypeA && TypeAEnabled(mode) {
		log.Printf("Request for %s (mode %d), replying with %v", name, mode, ip)
		m.Answer[0] = &A{Hdr: RR_Header{Name: name, Rrtype: TypeA, Class: ClassINET, Ttl: 1}, A: ip}
	} else if qtype == TypeAAAA && TypeAAAAEnabled(mode) {
		ip = EmbedIPv4InIPv6(ip)
		log.Printf("Request for %s (mode %d), replying with %v", name, mode, ip)
		m.Answer[0] = &AAAA{Hdr: RR_Header{Name: name, Rrtype: TypeAAAA, Class: ClassINET, Ttl: 1}, AAAA: ip}
	} else {
		log.Printf("Request for %s (mode %d), replying with empty response", name, mode)
	}
}

func main() {
	go Cleaner()

	err := ListenAndServe("0.0.0.0:53", "udp", HandlerFunc(HandleRequest))
	if err != nil {
		fmt.Println(err)
	}
}
