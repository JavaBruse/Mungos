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
		line := scanner.Text()
		if strings.Contains(line, "(base 16)") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				prefix := parts[0]
				vendor := strings.Join(parts[2:], " ")
				ouiMap[prefix] = vendor
			}
		}
	}

	return scanner.Err()
}

func GetVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	clean := strings.ReplaceAll(mac, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	if len(clean) >= 6 {
		prefix := strings.ToUpper(clean[:6])
		if vendor, ok := ouiMap[prefix]; ok {
			return vendor
		}
	}
	return ""
}
