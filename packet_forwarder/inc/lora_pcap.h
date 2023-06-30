#ifndef _LORA_PKTFWD_LORA_PCAP_H
#define _LORA_PKTFWD_LORA_PCAP_H

#define __USE_POSIX199309 1 /* Have time.h emit struct timespec */ 
/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
    #define _XOPEN_SOURCE 600
#else
    #define _XOPEN_SOURCE 500
#endif

#include <sys/time.h>
#include <time.h>
#include "loragw_hal.h"

struct lora_pcap_session_struct;
typedef struct lora_pcap_session_struct lora_pcap_session;

lora_pcap_session *lora_pcap_session_new(const char *path, uint64_t gw_eui);

int lora_pcap_session_start(lora_pcap_session *ps);

int lora_pcap_session_write(lora_pcap_session *ps,
    const struct lgw_pkt_rx_s *p, const struct timespec *ts);

int lora_pcap_session_flush(lora_pcap_session *ps);

int lora_pcap_session_stop(lora_pcap_session *ps);

void lora_pcap_session_free(lora_pcap_session *ps);

#endif
