package memory

import (
	"bufio"
	"os"
	"strings"
)

var ouiMap map[string]string

func InitOUIDatabase(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	ouiMap = make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "(base 16)") || strings.Contains(line, "(hex)") {
			idx := strings.Index(line, ")")
			if idx == -1 {
				continue
			}
			prefixPart := strings.Fields(line[:idx])
			if len(prefixPart) == 0 {
				continue
			}
			prefix := prefixPart[0]
			vendor := strings.TrimSpace(line[idx+1:])
			if vendor == "" {
				continue
			}

			ouiMap[prefix] = vendor
		}
	}

	return scanner.Err()
}

func GetVendor(mac string, ip string, port uint16) string {
	if mac != "" {
		clean := strings.ReplaceAll(mac, ":", "")
		clean = strings.ReplaceAll(clean, "-", "")
		if len(clean) >= 6 {
			prefix := strings.ToUpper(clean[:6])
			if vendor, ok := ouiMap[prefix]; ok {
				return vendor
			}
		}
	}

	return classifyTrafficType(ip, port)
}

func classifyTrafficType(ip string, port uint16) string {
	if ip == "255.255.255.255" {
		return "Broadcast"
	}

	if ip == "239.255.255.250" && port == 1900 {
		return "SSDP"
	}

	if ip == "224.0.0.251" && port == 5353 {
		return "mDNS"
	}

	if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") {
		return "Multicast"
	}
	return ""
}
