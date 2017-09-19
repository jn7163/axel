bin_PROGRAMS = axel
axel_SOURCES = axel.c conf.c conn.c ftp.c http.c search.c ssl.c tcp.c text.c \
	libtls/tls.c libtls/tls_client.c libtls/tls_config.c libtls/compat.c \
	libtls/tls_bio_cb.c libtls/tls_conninfo.c libtls/tls_ocsp.c \
	libtls/tls_util.c libtls/tls_verify.c

AM_CPPFLAGS = -DLOCALEDIR=\""$(localedir)"\"
AM_CPPFLAGS += -D_BSD_SOURCE -D_DEFAULT_SOURCE
