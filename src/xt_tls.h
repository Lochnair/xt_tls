#ifndef _XT_TLS_TARGET_H
#define _XT_TLS_TARGET_H

#define XT_TLS_OP_HOST	0x01

/* target info */
struct xt_tls_info {
	__u8 invert;
	char tls_host[255];
};

#endif /* _XT_TLS_TARGET_H */
