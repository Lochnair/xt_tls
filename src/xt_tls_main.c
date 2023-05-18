#define pr_fmt(fmt) "[" KBUILD_MODNAME "]: " fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <asm/errno.h>

#include "compat.h"
#include "xt_tls.h"
#include "hostset.h"

// The maximum number of host sets
static int max_host_sets = 8;
module_param(max_host_sets, int, S_IRUGO);
MODULE_PARM_DESC(max_host_sets, "host set table capacity (default 8)");

// The table of the host sets we use
static struct host_set *host_set_table;

// The proc-fs subdirectory for hostsets
struct proc_dir_entry *proc_fs_dir, *proc_fs_hostset_dir;

/*
 * Searches through skb->data and looks for a
 * client or server handshake. A client
 * handshake is preferred as the SNI
 * field tells us what domain the client
 * wants to connect to.
 */
static int get_tls_hostname(const struct sk_buff *skb, char **dest)
{
	char *data, *tail;
	size_t data_len;
	u_int16_t tls_header_len;
	u_int8_t handshake_protocol;
	bool data_buf_allocated = false;
        
#define free_data_buf() \
	if (data_buf_allocated) \
		kfree(data);

	struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb);
	size_t tcp_header_len = tcp_header->doff * 4;
	size_t payload_len = skb->len - skb_transport_offset(skb) - tcp_header_len;
#ifdef XT_TLS_DEBUG
	printk("[xt_tls] skb->len=%u, skb_transport_offset=%u\n", skb->len, skb_transport_offset(skb));
	printk("[xt_tls] tcp-header-length=%zu,  payload-length=%zu\n", tcp_header_len, payload_len);
	printk("[xt_tls] tcp_header=%px\n", tcp_header);
	printk("[xt_tls] tcp_header[]: %60ph\n", tcp_header);
	printk("[xt_tls] tcp_header->doff=%u\n", tcp_header->doff);
#endif

        // Check if entire packet data is here
	tail = skb_tail_pointer(skb);
#ifdef XT_TLS_DEBUG
	printk("[xt_tls] skb-tail=%px\n", tail);
#endif
	// First set the packet payload pointer right after the TCP-header
	// as if we were sure that the entire packet resides in the linear address space
	data = (char *)tcp_header + (tcp_header->doff * 4);
	// Calculate the length of the available packet data portion
	data_len = (uintptr_t)tail - (uintptr_t)data;
	// ...and check if we really have the entire packet
	if (data_len < payload_len) {
	        // if not - copy the missing portion from wherever it is
#ifdef XT_TLS_DEBUG
		printk("[xt_tls] Not all payload available right now - try to gather it\n");
#endif
		data = kmalloc(payload_len, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
		data_buf_allocated = true;
		if (skb_copy_bits(skb, skb_transport_offset(skb) + tcp_header_len, data, payload_len)) {
			kfree(data);
			return EPROTO;
		}//if
		data_len = payload_len;
	}//if

#ifdef XT_TLS_DEBUG
	printk("[xt_tls] data=%px\n", data);
	printk("[xt_tls] data[]: %64ph\n", data);
	printk("[xt_tls] Content-type=0x%X\n", (unsigned char)data[0]);
#endif
	// If this isn't an TLS handshake, abort
	if (data[0] != 0x16) {
#ifdef XT_TLS_DEBUG
		printk("[xt_tls] Not TLS handshaking\n");
#endif
		free_data_buf();
		return EPROTO;
	}

	tls_header_len = ((unsigned char)data[3] << 8) + (unsigned char)data[4] + 5;
	handshake_protocol = data[5];
#ifdef XT_TLS_DEBUG
	printk("[xt_tls] tls_header_len=%u, data_len=%zu\n", tls_header_len, data_len);
#endif

	// Even if we don't have all the data, try matching anyway
	if (tls_header_len > data_len)
		tls_header_len = data_len;

	if (tls_header_len > 4) {
		// Check only client hellos for now
		if (handshake_protocol == 0x01) {
			u_int offset, base_offset = 43, extension_offset = 2;
			u_int16_t session_id_len, cipher_len, compression_len, extensions_len;

			if (base_offset + 2 > data_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] Data length is to small (%d)\n", (int)data_len);
#endif
				free_data_buf();
				return EPROTO;
			}

			// Get the length of the session ID
			session_id_len = data[base_offset];

#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Session ID length: %d\n", session_id_len);
#endif
			if ((session_id_len + base_offset + 2) > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than session_id_len + base_offset +2 (%d > %d)\n", (session_id_len + base_offset + 2), tls_header_len);
#endif
				free_data_buf();
				return EPROTO;
			}

			// Get the length of the ciphers
			memcpy(&cipher_len, &data[base_offset + session_id_len + 1], 2);
			cipher_len = ntohs(cipher_len);
			offset = base_offset + session_id_len + cipher_len + 2;
#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Cipher len: %d\n", cipher_len);
			printk("[xt_tls] Offset (1): %d\n", offset);
#endif
			if (offset > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than offset (%d > %d)\n", offset, tls_header_len);
#endif
				free_data_buf();
				return EPROTO;
			}

			// Get the length of the compression types
			compression_len = data[offset + 1];
			offset += compression_len + 2;
#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Compression length: %d\n", compression_len);
			printk("[xt_tls] Offset (2): %d\n", offset);
#endif
			if (offset > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than offset w/compression (%d > %d)\n", offset, tls_header_len);
#endif
				free_data_buf();
				return EPROTO;
			}

			// Get the length of all the extensions
			memcpy(&extensions_len, &data[offset], 2);
			extensions_len = ntohs(extensions_len);
#ifdef XT_TLS_DEBUG
			printk("[xt_tls] Extensions length: %d\n", extensions_len);
#endif

			if ((extensions_len + offset) > tls_header_len) {
#ifdef XT_TLS_DEBUG
				printk("[xt_tls] TLS header length is smaller than offset w/extensions (%d > %d)\n", (extensions_len + offset), tls_header_len);
#endif
				free_data_buf();
				return EPROTO;
			}

			// Loop through all the extensions to find the SNI extension
			while (extension_offset < extensions_len)
			{
				u_int16_t extension_id, extension_len;

				memcpy(&extension_id, &data[offset + extension_offset], 2);
				extension_offset += 2;

				memcpy(&extension_len, &data[offset + extension_offset], 2);
				extension_offset += 2;

				extension_id = ntohs(extension_id), extension_len = ntohs(extension_len);

#ifdef XT_TLS_DEBUG
				printk("[xt_tls] Extension ID: %d\n", extension_id);
				printk("[xt_tls] Extension length: %d\n", extension_len);
#endif

				if (extension_id == 0) {
					u_int16_t name_length, name_type;

					// We don't need the server name list length, so skip that
					extension_offset += 2;
					// We don't really need name_type at the moment
					// as there's only one type in the RFC-spec.
					// However I'm leaving it in here for
					// debugging purposes.
					name_type = data[offset + extension_offset];
					extension_offset += 1;

					memcpy(&name_length, &data[offset + extension_offset], 2);
					name_length = ntohs(name_length);
					extension_offset += 2;

#ifdef XT_TLS_DEBUG
					printk("[xt_tls] Name type: %d\n", name_type);
					printk("[xt_tls] Name length: %d\n", name_length);
#endif
					// Allocate an extra byte for the null-terminator
					*dest = kmalloc(name_length + 1, GFP_KERNEL);
					strncpy(*dest, &data[offset + extension_offset], name_length);
					// Make sure the string is always null-terminated.
					(*dest)[name_length] = 0;

					free_data_buf();
					return 0;
				}

				extension_offset += extension_len;
			}
		}
	}

	free_data_buf();
	return EPROTO;
}

static bool tls_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	char *parsed_host;
	const struct xt_tls_info *info = par->matchinfo;
	int result;
	
	int pattern_type = (info->op_flags & XT_TLS_OP_HOSTSET) ?
	    XT_TLS_OP_HOSTSET : XT_TLS_OP_HOST;
	bool invert = (pattern_type == XT_TLS_OP_HOSTSET) ?
	    (info->inversion_flags & XT_TLS_OP_HOSTSET) :
	    (info->inversion_flags & XT_TLS_OP_HOST);
	bool suffix_matching = info->op_flags & XT_TLS_OP_SUFFIX;
	bool match;

	if ((result = get_tls_hostname(skb, &parsed_host)) != 0)
		return false;

	switch (pattern_type) {
	    case XT_TLS_OP_HOST:
		match = glob_match(info->host_or_set_name, parsed_host);
		break;
	    case XT_TLS_OP_HOSTSET:
		match = hs_lookup(&host_set_table[info->hostset_index], 
			parsed_host, suffix_matching);
		break;
	}//switch

#ifdef XT_TLS_DEBUG
	printk("[xt_tls] Parsed domain: %s\n", parsed_host);
	printk("[xt_tls] Domain matches: %s, invert: %s\n", match ? "true" : "false", invert ? "true" : "false");
#endif
	if (invert)
		match = !match;

	kfree(parsed_host);

	return match;
}


static int tls_mt_check (const struct xt_mtchk_param *par)
{
	__u16 proto;
	struct xt_tls_info *match_info = par->matchinfo;

	if (par->family == NFPROTO_IPV4) {
		proto = ((const struct ipt_ip *) par->entryinfo)->proto;
	} else if (par->family == NFPROTO_IPV6) {
		proto = ((const struct ip6t_ip6 *) par->entryinfo)->proto;
	} else {
		return -EINVAL;
	}

	if (proto != IPPROTO_TCP) {
		pr_info("Can be used only in combination with -p tcp\n");
		return -EINVAL;
	}
	
	// If the rule contains --tls-hostset, try to find an existing matching
	// hostset table entry or allocate a new one
	if (match_info->op_flags & XT_TLS_OP_HOSTSET) {
	    int i;
	    bool found = false;
	    
	    for (i = 0; i < max_host_sets; i++) {
		found = !hs_is_free(&host_set_table[i]) && 
		    strcmp(host_set_table[i].name, match_info->host_or_set_name) == 0;
		if (found)
		    break;
	    }//for
	    
	    if (found) {
		hs_hold(&host_set_table[i]);
	    } else {
		int rc;
		for (i = 0; i < max_host_sets; i++) {
		    found = hs_is_free(&host_set_table[i]);
		    if (found)
			break;
		}//for
		if (!found) {
		    pr_err("Cannot add a new hostset: the hostset table is full\n");
		    return -ENOMEM;
		}//if
		rc = hs_init(&host_set_table[i], match_info->host_or_set_name);
		if (rc)
		    return rc;
	    }//if
	    
	    match_info->hostset_index = i;
	}//if

	return 0;
}


static void tls_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_tls_info *match_info = par->matchinfo;
#ifdef XT_TLS_DEBUG
	pr_info("tls_mt_destroy: match_info: op_flags=0x%X, hostset_index=%u\n", 
		match_info->op_flags, match_info->hostset_index);
#endif
	if (match_info->op_flags & XT_TLS_OP_HOSTSET) {
	    hs_free(&host_set_table[match_info->hostset_index]);
	}//if
}//tls_mt_destroy


static struct xt_match tls_mt_regs[] __read_mostly = {
	{
		.name       = "tls",
		.revision   = 1,
		.family     = NFPROTO_IPV4,
		.checkentry = tls_mt_check,
		.destroy    = tls_mt_destroy,
		.match      = tls_mt,
		.matchsize  = sizeof(struct xt_tls_info),
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name       = "tls",
		.revision   = 1,
		.family     = NFPROTO_IPV6,
		.checkentry = tls_mt_check,
		.destroy    = tls_mt_destroy,
		.match      = tls_mt,
		.matchsize  = sizeof(struct xt_tls_info),
		.me         = THIS_MODULE,
	},
#endif
};


static int __net_init tls_net_init(struct net *net)
{
    proc_fs_dir = proc_mkdir(KBUILD_MODNAME, net->proc_net);
    proc_fs_hostset_dir = proc_mkdir(PROC_FS_HOSTSET_SUBDIR, proc_fs_dir);
    if (! proc_fs_hostset_dir) {
	pr_err("Cannot create /proc/net/ subdirectory for this module\n");
	return -EFAULT;
    }//if
    return 0;
}//tls_net_init


static void __net_exit tls_net_exit(struct net *net)
{
    proc_remove(proc_fs_hostset_dir);
    proc_remove(proc_fs_dir);
}//tls_net_exit


static struct pernet_operations tls_net_ops = {
    .init = tls_net_init,
    .exit = tls_net_exit,
};


static int __init tls_mt_init (void)
{
	int i;
	int rc = xt_register_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
	if (rc)
	    return rc;
	
	rc = register_pernet_subsys(&tls_net_ops);
	if (rc) {
	    pr_err("Cannot register pernet subsys\n");
	    xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
	    unregister_pernet_subsys(&tls_net_ops);
	    return rc;
	}//if
	
	host_set_table = kmalloc(sizeof (struct host_set) * max_host_sets, GFP_KERNEL);
	if (! host_set_table) {
	    pr_err("Cannot allocate memory for the host set table\n");
	    xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
	    return -ENOMEM;
	}//if
#ifdef XT_TLS_DEBUG
	pr_info("Host set table allocated (%u elements max)\n", max_host_sets);
#endif
	
	for (i = 0; i < max_host_sets; i++)
	    hs_zeroize(&host_set_table[i]);
	
	return 0;
}

static void __exit tls_mt_exit (void)
{
	int i;
	xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
	
	for (i = 0; i < max_host_sets; i++)
	    hs_destroy(&host_set_table[i]);
	kfree(host_set_table);
	unregister_pernet_subsys(&tls_net_ops);
#ifdef XT_TLS_DEBUG
	pr_info("Host set table disposed\n");
#endif
}

module_init(tls_mt_init);
module_exit(tls_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nils Andreas Svee <nils@stokkdalen.no>");
MODULE_DESCRIPTION("Xtables: TLS (SNI) matching");
MODULE_VERSION("0.3.4");
MODULE_ALIAS("ipt_tls");
