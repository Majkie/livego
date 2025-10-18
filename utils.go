package livego

import (
	"net"
	"net/http"
	"strings"
)

func getClientIP(r *http.Request) string {
	headers := []string{
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Real-IP",
		"X-Forwarded-For",
		"X-Client-IP",
		"X-Forwarded",
		"Forwarded-For",
		"Forwarded",
	}

	for _, header := range headers {
		ip := r.Header.Get(header)
		if ip == "" {
			continue
		}

		if header == "X-Forwarded-For" {
			ips := strings.Split(ip, ",")
			if len(ips) > 0 {
				ip = strings.TrimSpace(ips[0])
			}
		}

		if validIP := parseAndValidateIP(ip); validIP != "" {
			return validIP
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func parseAndValidateIP(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)

	if ipStr == "" {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	if isPrivateIP(ip) {
		return ""
	}

	return ip.String()
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	if ip.To4() != nil {
		privateRanges := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
		}

		for _, cidr := range privateRanges {
			_, privateNet, _ := net.ParseCIDR(cidr)
			if privateNet.Contains(ip) {
				return true
			}
		}
	}

	if ip.To4() == nil {
		privateRanges := []string{
			"fc00::/7",
			"fe80::/10",
		}

		for _, cidr := range privateRanges {
			_, privateNet, _ := net.ParseCIDR(cidr)
			if privateNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}
