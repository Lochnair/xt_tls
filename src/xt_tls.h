#ifndef _XT_TLS_TARGET_H
#define _XT_TLS_TARGET_H

#define XT_TLS_OP_HOST      0x01
#define XT_TLS_OP_HOSTSET   0x02
#define XT_TLS_OP_SUFFIX    0x04

#define MAX_HOSTNAME_LEN 255
#define MAX_HOSTSET_NAME_LEN 31

/* target info */
struct xt_tls_info {
	__u16 op_flags, inversion_flags;
	char host_or_set_name[MAX_HOSTNAME_LEN + 1];
        struct host_set *hostset;
};

#define PROC_FS_MODULE_DIR "xt_tls"
#define PROC_FS_HOSTSET_SUBDIR "hostset"

#endif /* _XT_TLS_TARGET_H */
