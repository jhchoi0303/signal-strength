#pragma pack(1)

struct IEEE80211_beacon_frame {
  uint8_t subtype;
  uint8_t flags;
  uint16_t duration;
  mac_address receiver_address;
  mac_address transmitter_address;
  mac_address bss_id;
  uint16_t seq;
  uint16_t fixedParam[6];
};



