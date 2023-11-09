package ble_sniff

import (
	"strconv"
	"strings"
	"time"

	"github.com/bettercap/gatt"
)

func onProprietary(btleData map[string]interface{}) {

	advert_address, ok := btleData["btle.advertising_address"].(string)
	if !ok {
		return
	}

	advertising_data, ok := btleData["btcommon.eir_ad.advertising_data"].(map[string]interface{})
	if !ok {
		return
	}

	eir_ad_entry, ok := advertising_data["btcommon.eir_ad.entry"].(map[string]interface{})
	if !ok {
		return
	}

	data, ok := eir_ad_entry["btcommon.eir_ad.entry.data"].(string)
	if !ok {
		data = "No data could be retrieved"
	}

	company_code_string, ok := eir_ad_entry["btcommon.eir_ad.entry.company_id"].(string)
	if !ok {
		return
	}

	company_code_hex := strings.Replace(company_code_string, "0x", "", -1)
	company_code, _ := strconv.ParseUint(company_code_hex, 16, 16)
	company_name := gatt.CompanyIdents[uint16(company_code)]

	NewSnifferEvent(time.Now(),
		"BLE ADVERT",
		advert_address,
		"BROADCAST",
		data,
		"Proprietary %s Data",
		company_name,
	).Push()
}

func onAdvertisement(btleData map[string]interface{}) {
	onProprietary(btleData)
}
