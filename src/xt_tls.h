#ifndef _XT_TLS_TARGET_H
#define _XT_TLS_TARGET_H

#define XT_TLS_OP_HOST	0x01

/* target info */
struct xt_tls_info {
	__u8 invert;
	char tls_host[255];
};

#endif /* _XT_TLS_TARGET_H */

typedef struct {
	__u32 hash;
	__u8 *data;
	__u16 data_len;
	bool seen_chlo;
	bool seen_shlo;
} flow_data;

typedef enum {
	NAME_FOUND,
	NAME_NOT_FOUND,
	NO_HANDSHAKE,
	NOT_ENOUGH_DATA,
	PROTOCOL_ERROR
} Result;
