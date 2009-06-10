#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include "syslogd.h"

extern Debug;
extern char LocalHostName[MAXHOSTNAMELEN];  /**< our hostname */
extern char privkey[MAXPATHLEN];
extern char cert[MAXPATHLEN];


static uint32_t global_block_number;
static SSL_CTX  *ssl_global_conf;

static EVP_MD_CTX *sign_global_conf;
static const EVP_MD     *sign_method;

static EVP_PKEY     *eprivkey;
static EVP_PKEY     *epubkey;
static X509         *xcert;

/*!
 * Create Message hash and store it in msg_t::hash
 * @param message description struct
 * @param Message data
 * @param Message len
 * @see syslog_msg_message_create()
 * @todo support both SHA1 and SHA256
 */
int
syslog_sha1_msg(msg_t *msg, char *data, size_t len)
{
	SHA256_Data(data, len, msg->hash);
}


int
syslog_sign_init()
{
	SSL *ssl;

	sign_global_conf =  EVP_MD_CTX_create();
	EVP_MD_CTX_init(sign_global_conf);

	if (ssl = SSL_new(ssl_global_conf)) {
		dprintf("Try to get keys from TLS X.509 cert...\n");

		if (!(xcert = SSL_get_certificate(ssl))) {
			logerror("SSL_get_certificate() failed");
			SSL_free(ssl);
			return EXIT_FAILURE;
		}
		if (!(eprivkey = SSL_get_privatekey(ssl))) {
			logerror("SSL_get_privatekey() failed");
			SSL_free(ssl);
			return EXIT_FAILURE;
		}
		if (!(epubkey = X509_get_pubkey(xcert))) {
			logerror("X509_get_pubkey() failed");
			SSL_free(ssl);
			return EXIT_FAILURE;
		}
	}

	SSL_free(ssl);

	if (EVP_PKEY_DSA != EVP_PKEY_type(epubkey->type)) {
		dprintf("X.509 cert has no DSA key\n");
		EVP_PKEY_free(epubkey);
		eprivkey = NULL;
		epubkey = NULL;
	} else {
		dprintf("Got public and private key "
		    "from X.509 --> use type PKIX\n");

		sign_method = EVP_dss1();
	}
}

/*!
 * Get keys from files received from commandline and initialize ssl parts.
 *
 */
int
syslog_ssl_init()
{
	const char *keyfilename   = privkey;
	const char *certfilename  = cert;

	SSL_CTX *ctx;

	FILE *priv;
	FILE *certf;

	dprintf("Opening files: %s , %s\n", certfilename, keyfilename);

	SSL_library_init();
	
	if (!(ctx = SSL_CTX_new(SSLv23_method())))
		err(EXIT_FAILURE, "Cannot initialize SSL %s\n", ERR_error_string(ERR_get_error(), NULL));

	if (!(priv  = fopen(keyfilename,  "r")) || !(certf = fopen(certfilename, "r"))) {
		dprintf("Unable to open certfilenameificate file %s and private key file %s\n", certfilename, keyfilename);
		/** @bug RFC says that if I can't find certfilenameificate/private key file I have to generate new one */
		return EXIT_FAILURE;
	} 

	/* Close files */
	fclose(priv);
	fclose(certf);

	/* Open certfilename file and private key file */
	if (!SSL_CTX_use_PrivateKey_file(ctx, keyfilename, SSL_FILETYPE_PEM) ||
	    !SSL_CTX_use_certificate_chain_file(ctx, certfilename)) {
		dprintf("Unable to load key/certfilename files: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return EXIT_FAILURE;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		dprintf("Private key \"%s\" does not match "
		    "certificate \"%s\": %s",
		    keyfilename, certfilename,
		    ERR_error_string(ERR_get_error(), NULL));
		return EXIT_FAILURE;
	}

	(void)SSL_CTX_set_options(ctx,
	    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE);
	(void)SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

/*	if (SSL_CTX_set_tmp_dh(ctx, get_dh1024()) != 1)
		dprintf("SSL_CTX_set_tmp_dh() failed: %s",
		ERR_error_string(ERR_get_error(), NULL));*/

	ssl_global_conf = ctx;
	
}

char *
syslog_sign_buf(const char *buff, size_t len)
{
	char buf[SIGN_MAX_LENGTH+1];
	unsigned char sig_value[SIGN_B64SIGLEN_DSS];
	unsigned char sig_b64[SIGN_B64SIGLEN_DSS];
	unsigned sig_len = 0;
	char *signature;
	
	EVP_SignInit(sign_global_conf, sign_method);
	EVP_SignUpdate(sign_global_conf, buff, len);
	EVP_SignFinal(sign_global_conf, sig_value, &sig_len, eprivkey);

	b64_ntop(sig_value, sig_len, (char *)sig_b64, sizeof(sig_b64));
	signature = strdup((char *)sig_b64);

	dprintf("sign_string_sign('%s') --> '%s'\n",
	    buf, signature);

	return signature;
}

/*!
 * Create SD elements for hash block message 
 * @see syslog_msg_queue_add()
 * @bug Count sign is not possible when I don't know header
 * @bug increasing global_block_number in wrong function ?
 */
char *
syslog_sign_msg_create(struct msg_queue_head *msg_head)
{
	char *sd, *hash, *sign, *p, *si, *header;
	size_t size;
	syslog_msg_t first_msg;
	msg_t *msg;
	time_t  now;

	(void)time(&now);
	
	first_msg = 0;

	header = syslog_msg_header_create(15, LocalHostName, ctime(&now), "syslogd", -1, -1);
	
	/* Get size of hash block where I will store all hashes divided by space */
	size = (SYSLOG_MSG_QUEUE_LENGTH * SHA256_DIGEST_STRING_LENGTH) + (SYSLOG_MSG_QUEUE_LENGTH - 1);

	if ((hash = malloc( size * sizeof(char))) == NULL)
		return NULL;
	
	/* set p to start of hash block */
	p = hash;
	
	TAILQ_FOREACH(msg, msg_head, next) {
		snprintf(p, SHA256_DIGEST_STRING_LENGTH, "%s", msg->hash);
		/* Remove trailing \0 from digest string */
		p[SHA256_DIGEST_STRING_LENGTH - 1] = ' ';
		p += SHA256_DIGEST_STRING_LENGTH;
	}

	dprintf("hash block: %s -- %d\n", hash, global_block_number);

	/* RFC says that signature is calculated over the whole message with out SIGN SD element */
	asprintf(&sd, "%s [ssign VER=\"0121\" RSID=\"0\" SG=\"%d\" SPRI=\"0\" GBC=\"%d\" FMN=\"%"PRIu64"\" CNT=\"%d\" HB=\"%s\"]",
	    header, SYSLOG_MSG_QUEUE_SG_ID, global_block_number, first_msg, SYSLOG_MSG_QUEUE_LENGTH, hash);

	si = syslog_sign_buf(sd, strlen(sd));

	/* free old sd buffer */
	free(sd);
	
	asprintf(&sd, "%s [ssign VER=\"0121\" RSID=\"0\" SG=\"%d\" SPRI=\"0\" GBC=\"%d\" FMN=\"%"PRIu64"\" CNT=\"%d\" HB=\"%s\" SIGN=\"%s\"]",
	    header, SYSLOG_MSG_QUEUE_SG_ID, global_block_number, first_msg, SYSLOG_MSG_QUEUE_LENGTH, hash, si);


	dprintf("Hash BLock Message %s\n", sd);

        /* Increase global_block_number after creating another hash message */
	global_block_number++;

	free(hash);
	
	return sd;
}
