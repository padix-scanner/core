package discovery

type serviceInfo struct {
	name  serviceName
	ports []int
}

type serviceName string

const (
	ServiceFTP      serviceName = "FTP"
	ServiceSSH      serviceName = "SSH"
	ServiceSMTP     serviceName = "SMTP"
	ServiceDNS      serviceName = "DNS"
	ServiceHTTP     serviceName = "HTTP"
	ServicePOP3     serviceName = "POP3"
	ServiceIMAP     serviceName = "IMAP"
	ServiceSMB      serviceName = "SMB"
	ServiceIMAPS    serviceName = "IMAPS"
	ServicePOP3S    serviceName = "POP3S"
	ServiceMSSQL    serviceName = "Microsoft SQL Server"
	ServiceOracle   serviceName = "Oracle Database"
	ServiceMySQL    serviceName = "MySQL"
	ServiceRDP      serviceName = "RDP"
	ServicePostgres serviceName = "PostgreSQL"
	ServiceVNC      serviceName = "VNC"
	ServiceRedis    serviceName = "Redis"
)

var defaultServices = []serviceInfo{
	{name: "FTP", ports: []int{21}},
	{name: "SSH", ports: []int{22}},
	{name: "SMTP", ports: []int{25, 587}},
	{name: "DNS", ports: []int{53}},
	{name: "HTTP", ports: []int{80, 8080, 443, 8443}},
	{name: "POP3", ports: []int{110}},
	{name: "IMAP", ports: []int{143}},
	{name: "SMB", ports: []int{445}},
	{name: "IMAPS", ports: []int{993}},
	{name: "POP3S", ports: []int{995}},
	{name: "Microsoft SQL Server", ports: []int{1433}},
	{name: "Oracle Database", ports: []int{1521}},
	{name: "MySQL", ports: []int{3306}},
	{name: "RDP", ports: []int{3389}},
	{name: "PostgreSQL", ports: []int{5432}},
	{name: "VNC", ports: []int{5900}},
	{name: "Redis", ports: []int{6379}},
}
