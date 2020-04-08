package meraki

import (
	"fmt"
	"github.com/chrholme/go-syslog/internal/syslogparser"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ErrHostnameNotFound = &syslogparser.ParserError{"No hostname found"}
)

type Parser struct {
	buff           []byte
	cursor         int
	l              int
	header         header
	structuredData string
	message        string
	location       *time.Location
}

type header struct {
	priority  syslogparser.Priority
	version   int
	timestamp time.Time
	hostname  string
	appName   string
	procId    string
	msgId     string
}

func NewParser(buff []byte) *Parser {
	return &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}
}

func (p *Parser) Location(location *time.Location) {
	p.location = location
}

func (p *Parser) Parse() error {
	hdr, err := p.parseHeader()

	if err != nil {
		if err != ErrHostnameNotFound {
			return err
		}
	}

	p.header = hdr

	if p.cursor < p.l {
		p.message = string(p.buff[p.cursor:])
	}

	return nil
}

func (p *Parser) Dump() syslogparser.LogParts {
	return syslogparser.LogParts{
		"priority":        p.header.priority.P,
		"facility":        p.header.priority.F.Value,
		"severity":        p.header.priority.S.Value,
		"version":         p.header.version,
		"timestamp":       p.header.timestamp,
		"hostname":        p.header.hostname,
		"app_name":        p.header.appName,
		"proc_id":         p.header.procId,
		"msg_id":          p.header.msgId,
		"structured_data": p.structuredData,
		"message":         p.message,
	}
}

// HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
// Meraki messages are poorly structured so header data will be captured best effort
func (p *Parser) parseHeader() (header, error) {
	hdr := header{}

	pri, err := p.parsePriority()
	if err != nil {
		return hdr, err
	}

	hdr.priority = pri

	ver, err := p.parseVersion()
	if err != nil {
		return hdr, err
	}
	hdr.version = ver
	p.cursor++

	ts, err := p.parseTimestamp()
	if err != nil {
		return hdr, err
	}

	hdr.timestamp = ts

	host, err := p.parseHostname()
	if err != nil {
		return hdr, err
	}

	hdr.hostname = host

	appName, err := p.parseAppName(host)
	if err != nil {
		return hdr, err
	}

	hdr.appName = appName

	return hdr, nil
}

func (p *Parser) parsePriority() (syslogparser.Priority, error) {
	return syslogparser.ParsePriority(p.buff, &p.cursor, p.l)
}

func (p *Parser) parseVersion() (int, error) {
	return syslogparser.ParseVersion(p.buff, &p.cursor, p.l)
}

//Will look for 1st instance of a Unix Timestamp which is present in almost all message types.
//If none is found set to current time
func (p *Parser) parseTimestamp() (time.Time, error) {
	var ts time.Time
	log := string(p.buff)
	re := regexp.MustCompile(`(\d{10,}.\d{6,})`)
	tsStr := re.FindString(log)
	if tsStr == "" {
		return time.Now(), nil
	}
	timeparts := strings.Split(tsStr, ".")
	sec, err := strconv.ParseInt(timeparts[0], 10, 64)
	if err != nil {
		return ts, err
	}
	nano, err := strconv.ParseInt(timeparts[1], 10, 64)
	ts = time.Unix(sec, nano)
	return ts, nil
}

//Will look for hostname as a string in the form UUID_string if none is found return error
func (p *Parser) parseHostname() (string, error){
	var hostname string
	log := string(p.buff)
	re := regexp.MustCompile(`([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_\w+)`)
	hostname = re.FindString(log)
	if hostname == "" {
		return hostname, ErrHostnameNotFound
	}
	return hostname,nil
}

//Assume app name is the string following hostname which appears to be true for most cases
func (p *Parser) parseAppName(host string) (string, error){
	log := string(p.buff)
	i := strings.Index(log,host)
	if i == -1 {
		return "", nil
	}
	s := fmt.Sprint(log[i:])
	i = strings.Index(s," ")
	s = fmt.Sprint(s[i+1:])
	i = strings.Index(s, " ")
	s = fmt.Sprint(s[:i])
	return s, nil
}