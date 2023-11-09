package ble_sniff

import (
	"time"

	"github.com/bcicen/jstream"
	"github.com/bettercap/bettercap/session"
)

type Sniffer struct {
	session.SessionModule
	Stats         *SnifferStats
	Ctx           *SnifferContext
	pktSourceChan chan *jstream.MetaValue
}

func NewSniffer(s *session.Session) *Sniffer {
	mod := &Sniffer{
		SessionModule: session.NewSessionModule("ble.sniff", s),
		Ctx:           nil,
		Stats:         nil,
	}

	mod.Ctx = NewSnifferContext()

	mod.AddParam(session.NewBoolParameter("ble.sniff.verbose",
		"false",
		"If true, every captured and parsed packet will be sent to the events.stream for displaying, otherwise only the ones parsed at the application layer (sni, http, etc)."))

	mod.AddParam(session.NewStringParameter("ble.sniff.interface",
		"nRF Sniffer for Bluetooth LE",
		"",
		"extcap nRF Sniffer interface"))

	mod.AddParam(session.NewStringParameter("ble.sniff.source",
		"",
		"",
		"If set, the sniffer will read from this JSON file instead of the current interface."))

	mod.AddParam(session.NewStringParameter("ble.sniff.pcap",
		"",
		"",
		"If set, the sniffer will read from this PCAP file instead of the current interface."))

	mod.AddParam(session.NewStringParameter("ble.sniff.output",
		"",
		"",
		"If set, the sniffer will write to this json file."))

	mod.AddParam(session.NewStringParameter("ble.sniff.tshark",
		"tshark",
		"",
		"location of tshark command"))

	mod.AddHandler(session.NewModuleHandler("ble.sniff on", "",
		"Start blework sniffer in background.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("ble.sniff off", "",
		"Stop blework sniffer in background.",
		func(args []string) error {
			return mod.Stop()
		}))

	return mod
}

func (mod Sniffer) Name() string {
	return "ble.sniff"
}

func (mod Sniffer) Description() string {
	return "Sniff packets from bluefruit sniffer"
}

func (mod Sniffer) Author() string {
	return "<CSULB CECS 378 Group 6>"
}

func (mod *Sniffer) Configure() error {
	var err error
	if mod.Running() {
		return session.ErrAlreadyStarted(mod.Name())
	} else if err, mod.Ctx = mod.GetContext(); err != nil {
		if mod.Ctx != nil {
			mod.Ctx.Close()
			mod.Ctx = nil
		}
		return err
	}
	return nil
}

func (mod *Sniffer) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	return mod.SetRunning(true, func() {

		mod.Stats = NewSnifferStats()

		mod.pktSourceChan = jstream.NewDecoder(mod.Ctx.Reader, 3).Stream()
		for packet := range mod.pktSourceChan {
			if !mod.Running() {
				mod.Debug("end pkt loop")
				break
			}

			now := time.Now()
			if mod.Stats.FirstPacket.IsZero() {
				mod.Stats.FirstPacket = now
			}
			mod.Stats.LastPacket = now

			packet_map, ok := packet.Value.(map[string]interface{})
			if !ok {
				//add sniffer stats
				continue
			}

			btle_data, ok := packet_map["btle"].(map[string]interface{})
			if !ok {
				//add sniffer stats
				continue
			}

			access_address, ok := btle_data["btle.access_address"].(string)
			if !ok {
				return
			}

			if access_address == "0x8e89bed6" {
				onAdvertisement(btle_data)
				mod.Stats.NumAdvertisements++
			}

			mod.Stats.NumMatched++
		}
		mod.pktSourceChan = nil
	})
}

func (mod *Sniffer) Stop() error {
	return mod.SetRunning(false, func() {
		mod.Ctx.Close()
	})
}
