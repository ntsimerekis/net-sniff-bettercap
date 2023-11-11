package ble_sniff

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"

	"github.com/bettercap/bettercap/log"
	"github.com/bettercap/bettercap/session"

	"github.com/evilsocket/islazy/tui"
)

type SnifferContext struct {
	Reader        *bufio.Reader
	nRFProc       *exec.Cmd
	ControlIn     *os.File
	ControlOut    *os.File
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

		err, nRFScript := mod.StringParam("ble.sniff.extcapscript")
		if err != nil {
			return err, ctx
		}

		syscall.Mknod("/tmp/ble-sniff-tshark", syscall.S_IFIFO|0666, 0)
		syscall.Mknod("/tmp/ble-sniff-control-in", syscall.S_IFIFO|0666, 0)
		syscall.Mknod("/tmp/ble-sniff-control-out", syscall.S_IFIFO|0666, 0)

		ctx.ControlOut, _ = os.OpenFile("/tmp/ble-sniff-control-out", os.O_RDONLY|syscall.O_NONBLOCK, 0)

		ctx.nRFProc = exec.CommandContext(context.Background(), nRFScript, "--capture", "--extcap-interface", "/dev/ttyUSB0-4.0", "--fifo", "/tmp/ble-sniff-tshark", "--extcap-control-in", "/tmp/ble-sniff-control-in", "--extcap-control-out", "/tmp/ble-sniff-control-out", "--scan-follow-rsp", "--scan-follow-aux")

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
			ctx.TSharkProc = exec.CommandContext(context.Background(), tshark, "-T", "json", "-r", "/tmp/ble-sniff-tshark")
		} else {
			ctx.TSharkProc = exec.CommandContext(context.Background(), tshark, "-T", "json", "-r", ctx.PcapFile)
		}

		tsharkout, err := ctx.TSharkProc.StdoutPipe()
		if err != nil {
			return err, ctx
		}

		err = ctx.nRFProc.Start()
		if err != nil {
			return err, ctx
		} else {
			ctx.TSharkRunning = true
		}

		err = ctx.TSharkProc.Start()
		if err != nil {
			return err, ctx
		}

		time.Sleep(time.Duration(5) * time.Second)
		ctx.ControlIn, _ = os.OpenFile("/tmp/ble-sniff-control-in", os.O_WRONLY|syscall.O_NONBLOCK, 0)

		ctx.ControlIn.Write([]byte("T\000\000\002\000\000"))
		time.Sleep(time.Duration(1) * time.Second)
		ctx.ControlIn.Write([]byte("T\000\000\036\000\001[247, 141, 41, 2, 56, 95, 1]"))

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
		nRFProc:       nil,
		ControlIn:     nil,
		ControlOut:    nil,
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

		err = c.nRFProc.Process.Kill()
		if err != nil {
			log.Debug("killed extcap script")
		} else {
			log.Warning("could not kill extcap script")
		}

		c.ControlIn.Close()
		c.ControlOut.Close()
	}

	if c.OutputFile != nil {
		log.Debug("closing output")
		c.OutputFile.Close()
		log.Debug("output closed")
		c.OutputFile = nil
	}
}
