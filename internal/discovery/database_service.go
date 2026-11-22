package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"core/pkg/models"
)

type databaseVersion struct {
	Product string
	Version string
}

// discoverMySQLService detects a MySQL service on the target (port 3306).
// It performs a TCP connect and reads the server greeting packet for version data.
func discoverMySQLService(target string) ([]models.Service, error) {
	const port = 3306

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceMySQL),
		State:      "open",
		Confidence: "high",
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err == nil && n > 5 {
		if version, ok := parseMySQLGreeting(buf[:n]); ok {
			service.Product = version.Product
			if version.Version != "" {
				service.Technologies = []models.Technology{{
					Name:       version.Product,
					Version:    version.Version,
					Category:   "database",
					Confidence: "high",
					Source:     "MySQL handshake",
				}}
			}
		}
	}

	return []models.Service{service}, nil
}

func parseMySQLGreeting(packet []byte) (databaseVersion, bool) {
	if len(packet) < 6 {
		return databaseVersion{}, false
	}

	// MySQL packet: length(3) + sequence(1) + protocol(1) + version\0
	if packet[4] == 0xff {
		return databaseVersion{}, false
	}

	end := 5
	for end < len(packet) && packet[end] != 0 {
		end++
	}
	if end <= 5 {
		return databaseVersion{}, false
	}

	raw := strings.TrimSpace(string(packet[5:end]))
	if raw == "" || !strings.ContainsAny(raw, "0123456789") {
		return databaseVersion{}, false
	}

	product := "MySQL"
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "mariadb"):
		product = "MariaDB"
	case strings.Contains(lower, "percona"):
		product = "Percona Server"
	}

	version := extractDatabaseVersion(raw)
	if version == "" {
		version = raw
	}

	return databaseVersion{
		Product: product,
		Version: version,
	}, true
}

// discoverPostgreSQLService detects a PostgreSQL service on the target (port 5432).
func discoverPostgreSQLService(target string) ([]models.Service, error) {
	const port = 5432

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServicePostgres),
		State:      "open",
		Confidence: "high",
	}

	if version, ok := probePostgreSQLVersion(conn); ok {
		service.Product = version.Product
		if version.Version != "" {
			service.Technologies = []models.Technology{{
				Name:       version.Product,
				Version:    version.Version,
				Category:   "database",
				Confidence: "medium",
				Source:     "PostgreSQL startup",
			}}
		}
	}

	return []models.Service{service}, nil
}

func probePostgreSQLVersion(conn net.Conn) (databaseVersion, bool) {
	// SSLRequest: int32 length=8, int32 code=80877103
	sslRequest := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(sslRequest); err != nil {
		return databaseVersion{}, false
	}

	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		return databaseVersion{}, false
	}

	// If server wants SSL, version is not exposed pre-auth; confirm service identity only.
	if resp[0] == 'S' || resp[0] == 'N' {
		return databaseVersion{Product: "PostgreSQL"}, true
	}

	return databaseVersion{}, false
}

// discoverMSSQLService detects a Microsoft SQL Server service on the target (port 1433).
func discoverMSSQLService(target string) ([]models.Service, error) {
	const port = 1433

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceMSSQL),
		State:      "open",
		Confidence: "high",
	}

	if version, ok := probeMSSQLVersion(conn); ok {
		service.Product = version.Product
		if version.Version != "" {
			service.Technologies = []models.Technology{{
				Name:       version.Product,
				Version:    version.Version,
				Category:   "database",
				Confidence: "high",
				Source:     "TDS prelogin",
			}}
		}
	}

	return []models.Service{service}, nil
}

func probeMSSQLVersion(conn net.Conn) (databaseVersion, bool) {
	// TDS PreLogin packet with VERSION, ENCRYPTION, INSTOPT, THREADID, MARS.
	prelogin := buildMSSQLPreLogin()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(prelogin); err != nil {
		return databaseVersion{}, false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return databaseVersion{}, false
	}

	version, ok := parseMSSQLPreLoginResponse(buf[:n])
	if !ok {
		if isTDSPreLoginResponse(buf[:n]) {
			return databaseVersion{Product: "Microsoft SQL Server"}, true
		}
		return databaseVersion{}, false
	}

	return databaseVersion{
		Product: "Microsoft SQL Server",
		Version: version,
	}, true
}

func isTDSPreLoginResponse(packet []byte) bool {
	if len(packet) < 8 {
		return false
	}
	if packet[0] != 0x04 {
		return false
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[2:4]))
	return payloadLen >= 8 && payloadLen <= len(packet)
}

func buildMSSQLPreLogin() []byte {
	// Option data: VERSION(6) + ENCRYPTION(1) + INSTOPT(1) + THREADID(4) + MARS(1)
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // client version
		0x02,                   // encryption: NOT_SUP
		0x00,                   // instance name terminator
		0x00, 0x00, 0x00, 0x00, // thread id
		0x00, // MARS disabled
	}

	// Option headers: token(1) + offset(2) + length(2), terminated by 0xFF
	const optionHeaderLen = 5
	const optionCount = 5
	optionsLen := optionCount*optionHeaderLen + 1
	dataOffset := optionsLen

	options := make([]byte, 0, optionsLen)
	appendOption := func(token byte, offset, length int) {
		options = append(options, token)
		options = binary.BigEndian.AppendUint16(options, uint16(offset))
		options = binary.BigEndian.AppendUint16(options, uint16(length))
	}

	appendOption(0x00, dataOffset+0, 6)  // VERSION
	appendOption(0x01, dataOffset+6, 1)  // ENCRYPTION
	appendOption(0x02, dataOffset+7, 1)  // INSTOPT
	appendOption(0x03, dataOffset+8, 4)  // THREADID
	appendOption(0x04, dataOffset+12, 1) // MARS
	options = append(options, 0xFF)

	payload := append(options, data...)
	packetLen := 8 + len(payload)

	packet := make([]byte, 0, packetLen)
	packet = append(packet, 0x12, 0x01) // PreLogin, EOM
	packet = binary.BigEndian.AppendUint16(packet, uint16(packetLen))
	packet = append(packet, 0x00, 0x00, 0x01, 0x00) // SPID, PacketID, Window
	packet = append(packet, payload...)
	return packet
}

func parseMSSQLPreLoginResponse(packet []byte) (string, bool) {
	if len(packet) < 8 {
		return "", false
	}

	payloadLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if payloadLen > len(packet) {
		payloadLen = len(packet)
	}
	if payloadLen <= 8 {
		return "", false
	}

	payload := packet[8:payloadLen]
	for i := 0; i < len(payload); {
		token := payload[i]
		if token == 0xFF {
			break
		}
		if i+5 > len(payload) {
			break
		}

		offset := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
		i += 5

		if token != 0x00 || length < 6 {
			continue
		}
		if offset+length > len(payload) {
			continue
		}

		v := payload[offset : offset+length]
		major := int(v[0])
		minor := int(v[1])
		build := int(binary.BigEndian.Uint16(v[2:4]))
		sub := int(binary.BigEndian.Uint16(v[4:6]))
		if major == 0 {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d.%d", major, minor, build, sub), true
	}

	return "", false
}

// discoverOracleService detects an Oracle Database listener on the target (port 1521).
func discoverOracleService(target string) ([]models.Service, error) {
	const port = 1521

	address := net.JoinHostPort(target, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	service := models.Service{
		Port:       port,
		Protocol:   "TCP",
		Name:       string(ServiceOracle),
		State:      "open",
		Confidence: "high",
	}

	if version, ok := probeOracleVersion(conn); ok {
		service.Product = version.Product
		if version.Version != "" {
			service.Technologies = []models.Technology{{
				Name:       version.Product,
				Version:    version.Version,
				Category:   "database",
				Confidence: "medium",
				Source:     "TNS handshake",
			}}
		}
	}

	return []models.Service{service}, nil
}

func probeOracleVersion(conn net.Conn) (databaseVersion, bool) {
	packet := buildOracleTNSVersionProbe()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		return databaseVersion{}, false
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return databaseVersion{}, false
	}

	version, ok := parseOracleTNSVersion(buf[:n])
	if ok {
		return databaseVersion{Product: "Oracle Database", Version: version}, true
	}

	// Any TNS response still confirms Oracle listener.
	if n >= 2 && binary.BigEndian.Uint16(buf[0:2]) == uint16(n) {
		return databaseVersion{Product: "Oracle Database"}, true
	}

	return databaseVersion{}, false
}

func buildOracleTNSVersionProbe() []byte {
	// Minimal TNS connect packet requesting version info; listener typically
	// responds with refuse/resend containing version details.
	connectData := strings.Join([]string{
		"(DESCRIPTION=",
		"(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=padix)(HOST=scanner)(USER=scanner)))",
		"(ADDRESS=(PROTOCOL=tcp)(HOST=127.0.0.1)(PORT=1521))",
		")",
	}, "")

	payloadLen := 34 + len(connectData)
	packet := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(packet[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint16(packet[2:4], 0) // packet checksum
	packet[4] = 0x01                            // connect
	packet[5] = 0x00                            // reserved
	binary.BigEndian.PutUint16(packet[6:8], 0x0136)
	binary.BigEndian.PutUint16(packet[8:10], 0x012c)
	binary.BigEndian.PutUint16(packet[10:12], 0x8000)
	binary.BigEndian.PutUint16(packet[12:14], 0x0001)
	binary.BigEndian.PutUint16(packet[14:16], 0x0001)
	binary.BigEndian.PutUint32(packet[16:20], 0x0000003c)
	binary.BigEndian.PutUint16(packet[20:22], 0x0000)
	binary.BigEndian.PutUint16(packet[22:24], 0x0001)
	binary.BigEndian.PutUint16(packet[24:26], 0x0000)
	binary.BigEndian.PutUint16(packet[26:28], 0x0000)
	binary.BigEndian.PutUint16(packet[28:30], 0x0000)
	binary.BigEndian.PutUint32(packet[30:34], 0x00000000)
	copy(packet[34:], connectData)
	return packet
}

func parseOracleTNSVersion(packet []byte) (string, bool) {
	raw := strings.ToLower(string(packet))
	idx := strings.Index(raw, "(version=")
	if idx == -1 {
		idx = strings.Index(raw, "version=")
	}
	if idx == -1 {
		return "", false
	}

	start := idx + len("version=")
	if start > 0 && packet[start-1] == '(' {
		// already aligned for "(version="
	}
	// Find actual value start after "version="
	valueStart := strings.Index(strings.ToLower(string(packet[idx:])), "version=")
	if valueStart == -1 {
		return "", false
	}
	valueStart = idx + valueStart + len("version=")
	if valueStart >= len(packet) {
		return "", false
	}

	end := valueStart
	for end < len(packet) {
		c := packet[end]
		if (c >= '0' && c <= '9') || c == '.' {
			end++
			continue
		}
		break
	}
	if end <= valueStart {
		return "", false
	}

	version := string(packet[valueStart:end])
	if strings.Count(version, ".") < 1 {
		return "", false
	}
	return version, true
}

func extractDatabaseVersion(raw string) string {
	var token strings.Builder
	best := ""
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		isVersionChar := (c >= '0' && c <= '9') || c == '.'
		if isVersionChar {
			token.WriteByte(c)
			continue
		}

		if token.Len() > 0 {
			candidate := strings.Trim(token.String(), ".")
			if isBetterDatabaseVersion(candidate, best) {
				best = candidate
			}
			token.Reset()
		}
	}
	if token.Len() > 0 {
		candidate := strings.Trim(token.String(), ".")
		if isBetterDatabaseVersion(candidate, best) {
			best = candidate
		}
	}
	return best
}

func isBetterDatabaseVersion(candidate, best string) bool {
	if candidate == "" || !strings.Contains(candidate, ".") {
		return false
	}
	if candidate[0] == '.' || candidate[len(candidate)-1] == '.' {
		return false
	}

	parts := strings.Split(candidate, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for j := 0; j < len(part); j++ {
			if part[j] < '0' || part[j] > '9' {
				return false
			}
		}
	}
	// Avoid distro fragments like 0.22.04.1 when a real product version exists.
	if len(parts[0]) == 1 && parts[0][0] == '0' {
		return false
	}

	if best == "" {
		return true
	}

	bestParts := strings.Split(best, ".")
	candidateDots := len(parts) - 1
	bestDots := len(bestParts) - 1
	if candidateDots != bestDots {
		return candidateDots > bestDots
	}
	if len(parts[0]) != len(bestParts[0]) {
		return len(parts[0]) > len(bestParts[0])
	}
	return len(candidate) > len(best)
}
