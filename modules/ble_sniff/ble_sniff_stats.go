package ble_sniff

import (
	"time"

	"github.com/bettercap/bettercap/log"
)

type SnifferStats struct {
	NumAdvertisements uint64
	NumMatched        uint64
	NumDumped         uint64
	NumWrote          uint64
	Started           time.Time
	FirstPacket       time.Time
	LastPacket        time.Time
}

func NewSnifferStats() *SnifferStats {
	return &SnifferStats{
		NumAdvertisements: 0,
		NumMatched:        0,
		NumDumped:         0,
		Started:           time.Now(),
		FirstPacket:       time.Time{},
		LastPacket:        time.Time{},
	}
}

func (s *SnifferStats) Print() error {
	first := "never"
	last := "never"

	if !s.FirstPacket.IsZero() {
		first = s.FirstPacket.String()
	}
	if !s.LastPacket.IsZero() {
		last = s.LastPacket.String()
	}

	log.Info("Sniffer Started    : %s", s.Started)
	log.Info("First Packet Seen  : %s", first)
	log.Info("Last Packet Seen   : %s", last)
	log.Info("Advertisements	 : %d", s.NumAdvertisements)
	log.Info("Matched Packets    : %d", s.NumMatched)
	log.Info("Dumped Packets     : %d", s.NumDumped)

	return nil
}
