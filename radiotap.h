#pragma pack(1)

struct radiotap_header {
  uint8_t version;
  uint8_t pad;
  uint16_t len;
  uint32_t present;
  uint8_t flag;
  uint8_t rate;
  uint16_t freq;
  uint16_t chnFlag;
  uint8_t signal;
  uint8_t dummny;
  uint16_t rxflag;
  uint8_t antenna;
  uint8_t ant;
};

enum radiotap_present_flags {
	TSFT,
	FLAGS,
	RATE,
	CHANNEL,
	FHSS,
	DBM_ANTENNA_SIGNAL,
	DBM_ANTENNA_NOISE,
	LOCK_QUALITY,
	TX_ATTENUATION,
	DB_TX_ATTENUATION,
	DBM_TX_POWER,
	ANTENNA,
	DB_ANTENNA_SIGNAL,
	DB_ANTENNA_NOISE,
	RX_FLAGS,
	TX_FLAGS,
	RESERVED16,
	RESERVED17,
	CHANNEL_PLUS,
	MCS_INFORMATION,
	A_MPDU_STATUS,
	VHT_INFORMATION,
	FRAME_TIMESTAMP,
	HE_INFORMATION,
	HE_MU_INFORMATION,
	RESERVED25,
	ZERO_LENGTH_PSDU,
	L_SIG,
	TLVS,
	RADIOTAP_NS_NEXT,
	VENDOR_NS_NEXT,
	EXT
};