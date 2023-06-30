/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
    #define _XOPEN_SOURCE 600
#else
    #define _XOPEN_SOURCE 500
#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "loragw_hal.h"
#include "lora_pcap.h"
#include "cursor/cursor.h"

#define LINKTYPE_LORATAP 270
#define LW_SYNC 0x34

/*
 * The PCAP file header. Using clever runtime checking of the
 * magic number field, this structure can be written to disk
 * directly without care of the native CPU byte order.
 */
struct pcap_header {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t	 this_zone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network;
};

struct pcap_packet_header_ns {
	uint32_t tm_s;
	uint32_t tm_ns;
	uint32_t packet_length;
	uint32_t capture_length;
};

/*
 * This is the _packed_ representation of the LoRa TAP V1
 * encoding scheme used by WireShark. Unfortunately, it places
 * wider fields at misaligned offsets, making it unsafe to fill and
 * then serialize this structure to disk. As such, it is unused by
 * this code, but provided here for reference.
 */
struct pcap_lora_tap_header {
	uint8_t  lt_version;
	uint8_t  lt_padding;
	uint16_t lt_length;
	uint32_t channel_frequency_hz;
	uint8_t  channel_bandwidth;
	uint8_t  channel_spreading_factor;
	int8_t   rssi_packet;
	int8_t   rssi_max;
	int8_t   rssi_current;
	int8_t   rssi_snr;
	uint8_t  sync_word;
	/* Additions v1 */
	uint8_t  gw_eui[8];
	uint32_t timestamp_1mhz; /* !MISALIGNED */
	uint8_t  flags;
	uint8_t  coding_rate;
	uint16_t data_rate;      /* !MISALIGNED */
	uint8_t  if_channel;
	uint8_t  rf_chain;
	uint16_t tag;            /* !MISALIGNED */
};
static size_t kLoRaTapHeaderSize = 35;

struct lora_pcap_session_struct {
	char *path;
	FILE *fp;
	/* Cached copy of serialized gateway EUI */
	uint8_t eui[8];
};

static int write_header(FILE *f, uint32_t caplen);
static int write_rx_packet(FILE *f, const uint8_t gw_eui[8],
    const struct lgw_pkt_rx_s *p, const struct timespec *ts);
static int8_t encode_lora_tap_rssi_dbm(float rssi_dbm);
static int8_t encode_lora_tap_snr_db(float db_snr);

lora_pcap_session *
lora_pcap_session_new(const char *path, uint64_t eui)
{
	FILE *fp;
	char *path_copy;
	lora_pcap_session *ps;

	if ((fp = fopen(path, "ab")) == NULL)
		goto OpenFailed;

	if ((ps = malloc(sizeof(lora_pcap_session))) == NULL)
		goto MallocFailed;

	if ((path_copy = strdup(path)) == NULL)
		goto StrDupFailed;

	ps->fp = fp;
	ps->path = path_copy;
	ps->eui[0] = (eui >> 56) & 0xff;
	ps->eui[1] = (eui >> 48) & 0xff;
	ps->eui[2] = (eui >> 40) & 0xff;
	ps->eui[3] = (eui >> 32) & 0xff;
	ps->eui[4] = (eui >> 24) & 0xff;
	ps->eui[5] = (eui >> 16) & 0xff;
	ps->eui[6] = (eui >>  8) & 0xff;
	ps->eui[7] = (eui      ) & 0xff;

	return ps;

StrDupFailed:
	free(ps);
MallocFailed:
	fclose(fp);
OpenFailed:
	return NULL;
}

int
lora_pcap_session_start(lora_pcap_session *ps)
{
	assert(ps->fp != NULL);

	/*
	 * We may have opened an existing pcap file, in which case the
	 * header will already be present and we need not write a new one.
	 * Test for this by checking the file size.
	 */
	if (fseek(ps->fp, 0, SEEK_END) != 0)
		return -1;

	if (ftell(ps->fp) == 0)
		return write_header(ps->fp, 65536);

	return 0;
}

int
lora_pcap_session_write(lora_pcap_session *ps,
    const struct lgw_pkt_rx_s *p, const struct timespec *tm)
{
	assert(ps->fp != NULL);
	return write_rx_packet(ps->fp, ps->eui, p, tm);
}

int
lora_pcap_session_flush(lora_pcap_session *ps)
{
	assert(ps->fp != NULL);
	return fflush(ps->fp);
}

int
lora_pcap_session_stop(lora_pcap_session *ps)
{
	assert(ps->fp != NULL);

	fclose(ps->fp);
	ps->fp = NULL;

	return 0;
}

void
lora_pcap_session_free(lora_pcap_session *ps)
{
	free(ps->path);
	free(ps);
}

static int
write_header(FILE *f, uint32_t caplen)
{
	struct pcap_header h;
	int num;

	h.magic_number = 0xa1b23c4d; /* Nanosecond-resolution type */
	h.version_major = 2;
	h.version_minor = 4;
	h.this_zone = 0;
	h.sigfigs = 0;
	h.snaplen = caplen;
	h.network = LINKTYPE_LORATAP;

	num = fwrite(&h, sizeof(h), 1, f);
	fflush(f);

	return (num == 1) ? 0 : -1;
}

static int
write_rx_packet(FILE *f, const uint8_t gw_eui[8], const struct lgw_pkt_rx_s *p,
    const struct timespec *ts)
{
	struct pcap_packet_header_ns ph;
	uint8_t buf[kLoRaTapHeaderSize];

	if (p->modulation != MOD_LORA)
		/* We can only dump LoRa packets */
		return 0;

	/* Fill in a LoRa TAP header from the packet meta-data */
	struct cursor cur = cursor_new(buf, sizeof(buf));

	cursor_pack_be_u8(&cur, 1); /* lt_version */
	cursor_pack_be_u8(&cur, 0); /* lt_padding */
	cursor_pack_be_u16(&cur, kLoRaTapHeaderSize); /* lt_length */
	cursor_pack_be_u32(&cur, p->freq_hz);

	/*
	 * The HAL encodes bandwidth in a manner incompatible with
	 * the PCAP link format.
	 * pcap: bw = bandwidth / 125kHz
	 * hal : bw = enumeration(1=500kHz, 2=250kHz, 3=125kHz, ...)
	 */
	uint8_t channel_bandwidth;
	switch (p->bandwidth) {
	case BW_125KHZ: channel_bandwidth = 1; break;
	case BW_250KHZ: channel_bandwidth = 2; break;
	case BW_500KHZ: channel_bandwidth = 4; break;
	default:        channel_bandwidth = 0; break;
	}

	cursor_pack_be_u8(&cur, channel_bandwidth);

	/*
	 * The HAL and the PCAP format agree exactly (currently) on
	 * the encoding of channel spreading factors. On a good compiler
	 * this switch statement should be a no-op. Nonetheless, good
	 * coding practice dictates an explicit translation.
	 */
	uint8_t channel_spreading_factor;
	switch (p->datarate) {
	case DR_LORA_SF7:  channel_spreading_factor = 7; break;
	case DR_LORA_SF8:  channel_spreading_factor = 8; break;
	case DR_LORA_SF9:  channel_spreading_factor = 9; break;
	case DR_LORA_SF10: channel_spreading_factor = 10; break;
	case DR_LORA_SF11: channel_spreading_factor = 11; break;
	case DR_LORA_SF12: channel_spreading_factor = 12; break;
	default:           channel_spreading_factor = 0; break;
	}

	cursor_pack_be_u8(&cur, channel_spreading_factor);

	/* This is an SX1302 radio. It only reports two RSSI values. */
	const int8_t rssic_tap_encoded = encode_lora_tap_rssi_dbm(p->rssic);
	const int8_t rssis_tap_encoded = encode_lora_tap_rssi_dbm(p->rssis);

	cursor_pack_be_i8(&cur, rssis_tap_encoded); /* rssi_packet */
	cursor_pack_be_i8(&cur, rssic_tap_encoded); /* rssi_max */
	cursor_pack_be_i8(&cur, rssic_tap_encoded); /* rssi_current */
	cursor_pack_be_i8(&cur, encode_lora_tap_snr_db(p->snr)); /* rssi_snr */

	cursor_pack_be_u8(&cur, LW_SYNC); /* sync_word */

	/* V1 additions */
	cursor_put(&cur, gw_eui, 8);
	cursor_pack_be_u32(&cur, p->count_us); /* timestamp_1mhz */

	/*
	 * LoRa TAP V1 flags:
	 *
	 * 00000001 = FSK modulation (not implemented yet)
	 * 00000010 = Symbol I/Q is inverted (not implemented yet)
	 * 00000100 = Implicit header (not implemented yet)
	 * 00001000 = CRC OK
	 * 00010000 = CRC Bad
	 * 00100000 = CRC Not Present
	 */
	uint8_t flags = 0;
	switch (p->status) {
	case STAT_NO_CRC:  flags |= 0x20; break;
	case STAT_CRC_BAD: flags |= 0x10; break;
	case STAT_CRC_OK:  flags |= 0x80; break;
	}

	cursor_pack_be_u8(&cur, flags); /* coding_rate */

	uint8_t coding_rate;
	switch (p->coderate) {
	case CR_LORA_4_5: coding_rate = 5; break;
	case CR_LORA_4_6: coding_rate = 6; break;
	case CR_LORA_4_7: coding_rate = 7; break;
	case CR_LORA_4_8: coding_rate = 8; break;
	default:          coding_rate = 0; break;
	}

	cursor_pack_be_u8(&cur, coding_rate); /* coding_rate */

	/* This next field, data_rate, is redundant. Skip computing it */
	cursor_pack_be_u16(&cur, 0); /* data_rate (bits/sec) */
	cursor_pack_be_u8(&cur, p->if_chain); /* if_channel */
	cursor_pack_be_u8(&cur, p->rf_chain); /* rf_chain */
	cursor_pack_be_u16(&cur, 0); /* "tag". Unknown use */

	assert(cursor_remaining(&cur) == 0);

	ph.tm_s = ts->tv_sec;
	ph.tm_ns = ts->tv_nsec;
	/*
	 * The maximum LoRa packet size is 256 bytes in this library, so all
	 * packets fit, all the time.
	 */
	ph.capture_length = sizeof(buf) + p->size;
	ph.packet_length  = ph.capture_length;

	int res1 = fwrite(&ph, sizeof(ph), 1, f) == 1;
	int res2 = fwrite(buf, sizeof(buf), 1, f) == 1;
	int res3 = fwrite(p->payload, p->size, 1, f) == 1;

	return (res1 && res2 && res3) ? 0 : -1;
}

static int8_t
encode_lora_tap_rssi_dbm(float rssi_dbm)
{
	float rval = rssi_dbm + 139;

	if (rval > 127.0)
		return 127;
	if (rval < -128.0)
		return -128;

	return (int8_t) rval;
}

/*
 * Encode an SNR value (in dB) in a fixed-point, signed 8-bit format.
 *
 * This function encodes the SNR according to the specification. Earlier
 * versions of WireShark, however, have a decoder bug, as such, the SNR
 * will not be displayed properly there. Later versions fix it.
 * (Example buggy version: 2021-03-26)
 */
static int8_t
encode_lora_tap_snr_db(float db_snr)
{
	if (db_snr == 0.0)
		return 0;
	if (db_snr < 0) {
		float rval = db_snr * 4.0;
		if (rval < -128.0)
			return -128;
		return (int8_t) rval;
	}
	if (db_snr > 127.0)
		return 127;
	return (int8_t) db_snr;
}
