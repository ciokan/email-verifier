package emailverifier

import (
	"net"
)

// Mx is detail about the Mx host
type Mx struct {
	HasMXRecord bool      // whether has 1 or more MX record
	Records     []*net.MX // represent DNS MX records
}

// CheckMX will return the DNS MX records for the given domain name sorted by preference.
func (v *Verifier) CheckMX(domain string) (*Mx, error) {
	domain = domainToASCII(domain)
	mx, err := net.LookupMX(domain)
	if err != nil && len(mx) == 0 {
		return nil, err
	}

	var valids []*net.MX
	for i := range mx {
		// make sure the MX is a valid domain name or IP address
		ip := net.ParseIP(mx[i].Host)
		if ip != nil {
			// if it's a valid IP address, we can consider it valid
			valids = append(valids, mx[i])
			continue
		}

		if mx[i].Host != "" {
			if _, err := net.LookupHost(mx[i].Host); err == nil {
				valids = append(valids, mx[i])
			}
		}
	}

	return &Mx{
		HasMXRecord: len(valids) > 0,
		Records:     mx,
	}, nil
}
