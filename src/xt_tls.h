#ifndef _XT_TLS_TARGET_H
#define _XT_TLS_TARGET_H

#define XT_TLS_OP_GROUP	0x01
#define XT_TLS_OP_HOST	0x02

/* target info */
struct xt_tls_info {
	__u8 invert;
	__u8 match_type;
	char tls_group[255];
	char tls_host[255];
};

#endif /* _XT_TLS_TARGET_H */
