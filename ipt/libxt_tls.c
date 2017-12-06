#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "xt_tls.h"

enum {
	O_TLS_GROUP	= 0,
	O_TLS_HOST	= 1,
	O_TLS_PORT	= 2,
};

static void tls_help(void)
{
	printf(
"tls match options:\n[!] --tls-host hostname\n[!] --tls-group group\n"
	);
}

static const struct xt_option_entry tls_opts[] = {
	{
		.name = "tls-group",
		.id = O_TLS_GROUP,
		.type = XTTYPE_STRING,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tls_info, tls_group),
	},
	{
		.name = "tls-host",
		.id = O_TLS_HOST,
		.type = XTTYPE_STRING,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tls_info, tls_host),
	},
	XTOPT_TABLEEND,
};

static void tls_parse(struct xt_option_call *cb)
{
	struct xt_tls_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_TLS_GROUP:
			if (cb->invert)
				info->invert |= XT_TLS_OP_GROUP;
			break;
		case O_TLS_HOST:
			if (cb->invert)
				info->invert |= XT_TLS_OP_HOST;
			break;
	}
}

static void tls_check(struct xt_fcheck_call *cb)
{
	struct xt_tls_info *info = (struct xt_tls_info *)cb->data;

	if (strlen(info->tls_group) > 0 && strlen(info->tls_host) > 0)
		xtables_error(PARAMETER_PROBLEM, "TLS: can't use --tls-group and --tls-host at the same time");

	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "TLS: no tls option specified");
}

static void tls_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_tls_info *info = (const struct xt_tls_info *)match->data;

	printf(" TLS match");
	if (strlen(info->tls_group) > 0)
 		printf("%s --tls-group %s",
 				 	(info->invert & XT_TLS_OP_GROUP) ? " !":"", info->tls_group);

 	if (strlen(info->tls_host) > 0)
 		printf("%s --tls-host %s",
 				 	(info->invert & XT_TLS_OP_HOST) ? " !":"", info->tls_host);
}

static void tls_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tls_info *info = (const struct xt_tls_info *)match->data;

	if (strlen(info->tls_group) > 0)
		printf(" %s --tls-group %s",
				 	(info->invert & XT_TLS_OP_GROUP) ? " !":"", info->tls_group);

	if (strlen(info->tls_host) > 0)
		printf(" %s --tls-host %s",
				 	(info->invert & XT_TLS_OP_HOST) ? " !":"", info->tls_host);
}

static struct xtables_match tls_match = {
	.family					= NFPROTO_IPV4,
	.name						= "tls",
	.version				= XTABLES_VERSION,
	.size						= XT_ALIGN(sizeof(struct xt_tls_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tls_info)),
	.help						= tls_help,
	.print					= tls_print,
	.save						= tls_save,
	.x6_parse				= tls_parse,
	.x6_fcheck			= tls_check,
	.x6_options			= tls_opts,
};

void _init(void)
{
	xtables_register_match(&tls_match);
}
