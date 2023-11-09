package ble_sniff

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"

	"github.com/bettercap/bettercap/log"
	"github.com/bettercap/bettercap/session"

	"github.com/evilsocket/islazy/tui"
)

type SnifferContext struct {
	Reader        *bufio.Reader
	TSharkProc    *exec.Cmd
	TSharkRunning bool
	Interface     string
	Source        string
	PcapFile      string
	DumpLocal     bool
	Verbose       bool
	Filter        string
	Expression    string
	Compiled      *regexp.Regexp
	Output        string
	OutputFile    *os.File
}

func (mod *Sniffer) GetContext() (error, *SnifferContext) {
	var err error

	ctx := NewSnifferContext()

	if err, ctx.Source = mod.StringParam("ble.sniff.source"); err != nil {
		return err, ctx
	}

	if ctx.Source == "" {

		err, tshark := mod.StringParam("ble.sniff.tshark")
		if err != nil {
			return err, ctx
		}

		if err, ctx.Interface = mod.StringParam("ble.sniff.interface"); err != nil {
			return err, ctx
		}

		if err, ctx.PcapFile = mod.StringParam("ble.sniff.pcap"); err != nil {
			return err, ctx
		}

		if ctx.PcapFile == "" {
			ctx.TSharkProc = exec.CommandContext(context.Background(), tshark, "-i", ctx.Interface, "-T", "json")
		} else {
			ctx.TSharkProc = exec.CommandContext(context.Background(), tshark, "-T", "json", "-r", ctx.PcapFile)
		}

		tsharkout, err := ctx.TSharkProc.StdoutPipe()
		if err != nil {
			return err, ctx
		}

		err = ctx.TSharkProc.Start()
		if err != nil {
			return err, ctx
		} else {
			ctx.TSharkRunning = true
		}

		ctx.Reader = bufio.NewReader(tsharkout)

	} else {
		file_reader, err := os.Open(ctx.Source)
		if err != nil {
			return err, ctx
		}

		ctx.Reader = bufio.NewReader(file_reader)
	}

	if err, ctx.Output = mod.StringParam("ble.sniff.output"); err != nil {
		return err, ctx
	} else if ctx.Output != "" {
		if ctx.OutputFile, err = os.Create(ctx.Output); err != nil {
			return err, ctx
		}
	}

	return nil, ctx
}

func NewSnifferContext() *SnifferContext {
	return &SnifferContext{
		Reader:        nil,
		TSharkProc:    nil,
		TSharkRunning: false,
		Interface:     "",
		Source:        "",
		PcapFile:      "",
		DumpLocal:     false,
		Verbose:       false,
		Filter:        "",
		Expression:    "",
		Compiled:      nil,
		Output:        "",
		OutputFile:    nil,
	}
}

var (
	no  = tui.Red("no")
	yes = tui.Green("yes")
	yn  = map[bool]string{
		true:  yes,
		false: no,
	}
)

func (c *SnifferContext) Log(sess *session.Session) {
	log.Info("Skip local packets : %s", yn[c.DumpLocal])
	log.Info("Verbose            : %s", yn[c.Verbose])
	log.Info("BPF Filter         : '%s'", tui.Yellow(c.Filter))
	log.Info("Regular expression : '%s'", tui.Yellow(c.Expression))
	log.Info("File output        : '%s'", tui.Yellow(c.Output))
}

func (c *SnifferContext) Close() {

	if c.TSharkRunning {
		err := c.TSharkProc.Process.Kill()
		if err != nil {
			log.Debug("killed TSharkProc")
		} else {
			log.Warning("could not kill TShark Process")
		}
	}

	if c.OutputFile != nil {
		log.Debug("closing output")
		c.OutputFile.Close()
		log.Debug("output closed")
		c.OutputFile = nil
	}
}
