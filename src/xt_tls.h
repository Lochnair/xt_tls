#ifndef _XT_TLS_TARGET_H
#define _XT_TLS_TARGET_H

#define XT_TLS_OP_HOST      0x01
#define XT_TLS_OP_HOSTSET   0x02

/* target info */
struct xt_tls_info {
	__u8 invert;
	char tls_host[255];
};

#define PROC_FS_HOSTSET_DIR "net/xt_tls/hostset"
extern struct proc_dir_entry *proc_fs_hostset_dir;

#endif /* _XT_TLS_TARGET_H */
