#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "xt_tls.h"

enum {
	O_TLS_HOST = 0,
	O_TLS_HOSTSET = 1,
	O_TLS_SUFFIX = 2,
};

static void tls_help(void)
{
	printf(
		"tls match options:\n"
		"  [!] --tls-host hostname\n"
		"  [!] --tls-hostset [--tls-suffix] hostset-name\n"
		"  --tls-host and --tls-hostset are mutually exclusive\n"
		"  The content of the hostset <HS> is accessible through "
		    "/proc/net/"PROC_FS_MODULE_DIR"/"PROC_FS_HOSTSET_SUBDIR"/<HS>\n"
	);
}

static const struct xt_option_entry tls_opts[] = {
	{
		.name = "tls-host",
		.id = O_TLS_HOST,
		.type = XTTYPE_STRING,
		.size = MAX_HOSTNAME_LEN,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tls_info, host_or_set_name),
	},
	{
		.name = "tls-hostset",
		.id = O_TLS_HOSTSET,
		.type = XTTYPE_STRING,
		.size = MAX_HOSTSET_NAME_LEN,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tls_info, host_or_set_name),
	},
	{
		.name = "tls-suffix",
		.id = O_TLS_SUFFIX,
	},
	XTOPT_TABLEEND,
};

static void tls_parse(struct xt_option_call *cb)
{
	struct xt_tls_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_TLS_HOST:
			info->op_flags |= XT_TLS_OP_HOST;
			if (cb->invert)
				info->inversion_flags |= XT_TLS_OP_HOST;
			break;
		case O_TLS_HOSTSET:
			info->op_flags |= XT_TLS_OP_HOSTSET;
			if (cb->invert)
				info->inversion_flags |= XT_TLS_OP_HOSTSET;
			break;
		case O_TLS_SUFFIX:
			info->op_flags |= XT_TLS_OP_SUFFIX;
			break;
	}
}

static void tls_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "TLS: no tls option specified");
	if ((cb->xflags & O_TLS_HOST) && (cb->xflags & O_TLS_HOSTSET))
		xtables_error(PARAMETER_PROBLEM, 
			"TLS: --tls-host and --tls-hostset options can't be specified together");
}

static void tls_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_tls_info *info = (const struct xt_tls_info *)match->data;
	char *suffix_match = info->op_flags & XT_TLS_OP_SUFFIX ? "suffix-" : "";

	printf(" TLS %smatch", suffix_match);
	if (info->op_flags & XT_TLS_OP_HOST) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOST;
	    printf("%s host %s", invert ? " !":"", info->host_or_set_name);
	}//if
	
	if (info->op_flags & XT_TLS_OP_HOSTSET) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOSTSET;
	    printf("%s hostset %s", invert ? " !":"", info->host_or_set_name);
	}//if
}

static void tls_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tls_info *info = (const struct xt_tls_info *)match->data;

	if (info->op_flags & XT_TLS_OP_HOST) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOST;
	    printf("%s --tls-host %s", invert ? " !":"", info->host_or_set_name);
	}//if

	if (info->op_flags & XT_TLS_OP_HOSTSET) {
	    bool invert = info->inversion_flags & XT_TLS_OP_HOSTSET;
	    char *suffix_match = info->op_flags & XT_TLS_OP_SUFFIX ? " --tls-suffix" : "";
	    printf("%s --tls-hostset %s%s", invert ? " !":"", info->host_or_set_name,
		    suffix_match);
	}//if
}

static struct xtables_match tls_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "tls",
	.version	= XTABLES_VERSION,
	.revision	= 1,
	.size		= XT_ALIGN(sizeof(struct xt_tls_info)),
	.userspacesize	= offsetof(struct xt_tls_info, hostset_index),
	.help		= tls_help,
	.print		= tls_print,
	.save		= tls_save,
	.x6_parse	= tls_parse,
	.x6_fcheck	= tls_check,
	.x6_options	= tls_opts,
};

void _init(void)
{
	xtables_register_match(&tls_match);
}
