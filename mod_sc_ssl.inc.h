#ifndef _MOD_SC_SSL_H_
#define _MOD_SC_SSL_H_ 1

#ifndef _MOD_SC_H_
/* include mod_sc.h */
/* !include mod_sc.h */
#endif

/* compile time version of mod_sc */
/* !include mod_sc_version */

/* default ssl key and certificate */
/* !include default_pk */
/* !include default_crt */

typedef struct st_mod_sc_ssl		mod_sc_ssl_t;

struct st_mod_sc_ssl {
/* st_mod_sc included by Makefile.PL */
/* !include st_mod_sc */
/* ssl extension starts here */
	const char *sc_ssl_version; /* XS_VERSION */
	int (*sc_ssl_create_server_context) ( sc_t *socket );
	int (*sc_ssl_create_client_context) ( sc_t *socket );
	int (*sc_ssl_set_certificate) ( sc_t *socket, const char *fn );
	int (*sc_ssl_set_private_key) ( sc_t *socket, const char *fn );
	int (*sc_ssl_set_client_ca) ( sc_t *socket, const char *fn );
	int (*sc_ssl_set_verify_locations) (
		sc_t *socket, const char *cafile, const char *capath
	);
	int (*sc_ssl_check_private_key) ( sc_t *socket );
	int (*sc_ssl_enable_compatibility) ( sc_t *socket );
	const char *(*sc_ssl_get_cipher_name) ( sc_t *socket );
	const char *(*sc_ssl_get_cipher_version) ( sc_t *socket );
};

#endif /* _MOD_SC_SSL_H_ */
