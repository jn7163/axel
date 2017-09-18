/*
  Axel -- A lighter download accelerator for Linux and other Unices

  Copyright 2016      Sjjad Hashemian
  Copyright 2016-2017 Stephen Thirlwall
  Copyright 2017      Antonio Quartulli
  Copyright 2017      Ismael Luceno

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  In addition, as a special exception, the copyright holders give
  permission to link the code of portions of this program with the
  OpenSSL library under certain conditions as described in each
  individual source file, and distribute linked combinations including
  the two.

  You must obey the GNU General Public License in all respects for all
  of the code used other than OpenSSL. If you modify file(s) with this
  exception, you may extend this exception to your version of the
  file(s), but you are not obligated to do so. If you do not wish to do
  so, delete this exception statement from your version. If you delete
  this exception statement from all source files in the program, then
  also delete it here.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* SSL interface */

#include "axel.h"

#ifdef HAVE_SSL

static conf_t *conf = NULL;

int
ssl_init(conf_t *global_conf)
{
	conf = global_conf;
	return tls_init();
}

struct tls *
ssl_connect(int fd, char *hostname, char *message)
{
	struct tls *ctx;

	ctx = tls_client();
	if (!ctx) {
		sprintf(message, _("SSL error: can't create client object\n"));
		return NULL;
	}

	/* configure some SSL settings */
	struct tls_config *tls_conf = tls_config_new();
	if (tls_config_set_ca_path(tls_conf, SSL_CA_PATH) < 0) {
		fprintf(stderr, _("SSL error: %s\n"), tls_error(ctx));
		goto err;
	}

	/* deactivate cert verification if specified by the user */
	if (conf->insecure) {
		tls_config_insecure_noverifyname(tls_conf);
		tls_config_insecure_noverifycert(tls_conf);
	}

	if (tls_configure(ctx, tls_conf) < 0) {
		sprintf(message, _("SSL error: %s\n"),
			tls_config_error(tls_conf));
		goto err;
	}
	tls_config_free(tls_conf);

	if (tls_connect_socket(ctx, fd, hostname) < 0) {
		sprintf(message, _("SSL error: %s\n"), tls_error(ctx));
		goto err;
	}

	/* perform TLS handshake explicitly now to have a chance to get
	 * any error. Otherwise tls_read/write would do it implicitly for us
	 */
	if (tls_handshake(ctx) < 0) {
		sprintf(message, _("SSL error: %s\n"), tls_error(ctx));
		goto err;
	}

	return ctx;
err:
	ssl_disconnect(ctx);
	return NULL;
}

void
ssl_disconnect(struct tls *ctx)
{
	tls_close(ctx);
	tls_free(ctx);
}

#endif				/* HAVE_SSL */
