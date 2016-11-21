#ifndef _XT_SSL_TARGET_H
#define _XT_SSL_TARGET_H

#define XT_SSL_OP_HOST	0x01

/* target info */
struct xt_ssl_info {
	__u8 invert;
	char ssl_host[255];
};

#endif /* _XT_SSL_TARGET_H */
