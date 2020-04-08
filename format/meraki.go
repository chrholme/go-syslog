package format

import (
	"bufio"

	"github.com/chrholme/go-syslog/internal/syslogparser/meraki"
)

type Meraki struct{}

func (f *Meraki) GetParser(line []byte) LogParser {
	return &parserWrapper{meraki.NewParser(line)}
}

func (f *Meraki) GetSplitFunc() bufio.SplitFunc {
	return nil
}
