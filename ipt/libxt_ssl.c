#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "xt_ssl.h"

enum {
	O_SSL_HOST = 0,
	O_SSL_PORT = 1,
};

static void ssl_help(void)
{
	printf(
"ssl match options:\n[!] --ssl-host hostname\n--ssl-port port (default: 443)\n"
	);
}

static const struct xt_option_entry ssl_opts[] = {
	{
		.name = "ssl-host",
		.id = O_SSL_HOST,
		.type = XTTYPE_STRING,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_ssl_info, ssl_host),
	},
	{
		.name = "ssl-port",
		.id = O_SSL_PORT,
		.type = XTTYPE_UINT16,
		.flags = XTOPT_PUT, XTOPT_POINTER(struct xt_ssl_info, ssl_port),
	},
	XTOPT_TABLEEND,
};

static void ssl_parse(struct xt_option_call *cb)
{
	struct xt_ssl_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_SSL_HOST:
			if (cb->invert)
				info->invert |= XT_SSL_OP_HOST;
			break;
		case O_SSL_PORT:
			if (cb->arg == 0)
				info->ssl_port = 443;

	}
}

static void ssl_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "SSL: no ssl option specified");
}

static void ssl_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_ssl_info *info = (const struct xt_ssl_info *)match->data;

	printf(" SSL match");
	printf("%s --ssl-host %s",
				 (info->invert & XT_SSL_OP_HOST) ? " !":"", info->ssl_host);
	printf("--ssl-port %d", info->ssl_port);
}

static void ssl_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_ssl_info *info = (const struct xt_ssl_info *)match->data;

	printf(" %s --ssl-host %s",
				 (info->invert & XT_SSL_OP_HOST) ? " !":"", info->ssl_host);
	printf(" --ssl-port %d", info->ssl_port);
}

static struct xtables_match ssl_match = {
	.family					= NFPROTO_IPV4,
	.name						= "ssl",
	.version				= XTABLES_VERSION,
	.size						= XT_ALIGN(sizeof(struct xt_ssl_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_ssl_info)),
	.help						= ssl_help,
	.print					= ssl_print,
	.save						= ssl_save,
	.x6_parse				= ssl_parse,
	.x6_fcheck			= ssl_check,
	.x6_options			= ssl_opts,
};

void _init(void)
{
	xtables_register_match(&ssl_match);
}
