#ifndef __SYSLOG_H__
#define __SYSLOG_H__

#include <sys/syslog.h>
#include <openssl/sha.h>

/** Debug enabled printf */
#define	dprintf		if (Debug) printf

/** Signature id typedef */
typedef uint32_t syslog_sg_t;
typedef pid_t syslog_pid_t;
typedef uint64_t syslog_msg_t;

#define SYSLOG_VERSION  1               /**< Syslog protocol Version */
#define SYSLOG_MSG_QUEUE_SG_ID 0        /**< Syslog sign default Signature ID */
#define SYSLOG_MSG_QUEUE_LENGTH 3      /**< Syslog sign default length of message queue */

#define SHA256_DIGEST_STRING_LENGTH 65 /**< Size of SHA256 digest transformed to string */

#define MAX_TIMESTAMPLEN        31+1

/* maximum field lengths in syslog-protocol */
#define PRI_MAX       5
#define HOST_MAX    255
#define APPNAME_MAX  48
#define PROCID_MAX  128
#define MSGID_MAX    32
/* longest possible header length */
#define HEADER_LEN_MAX (PRI_MAX + 1 + 1 + MAX_TIMESTAMPLEN + 1 + HOST_MAX \
	    + 1 + APPNAME_MAX + 1 + PROCID_MAX + 1 + MSGID_MAX)

#define SIGN_MAX_LENGTH 2048
/* the length we can use for the SD and keep the
 * message length with header below 2048 octets */
#define SIGN_MAX_SD_LENGTH (SIGN_MAX_LENGTH - 1 - HEADER_LEN_MAX)
/* length of signature, currently only for DSA */
#define SIGN_B64SIGLEN_DSS 64+1

#define	MAXLINE		4096		/**< maximum line length */
#define	MAXSVLINE	120		/**< maximum saved line length */
#define DEFUPRI		(LOG_USER|LOG_NOTICE)
#define DEFSPRI		(LOG_KERN|LOG_NOTICE)
#define TIMERINTVL	30		/**< interval for checking flush, mark */
#define TTYMSGTIME	1		/**< timeout passed to ttymsg */

#define FDMASK(fd)	(1 << (fd))

#define MAXUNAMES	20	/**< maximum number of user names */

/*!
 * Flags to logmsg().
 * @param see logmsg()
 */

#define IGN_CONS	0x001	/* don't print on console */
#define SYNC_FILE	0x002	/* do fsync on file after printing */
#define ADDDATE		0x004	/* add a date to the message */
#define MARK		0x008	/* this message is a mark */
#define	ISKERNEL	0x010	/* kernel generated message */

/*!
 * Intervals at which we flush out "message repeated" messages,
 * in seconds after previous message is logged.  After each flush,
 * we move to the next interval until we reach the largest.
 */
#define	MAXREPEAT ((sizeof(repeatinterval) / sizeof(repeatinterval[0])) - 1)
#define	REPEATTIME(f)	((f)->f_time + repeatinterval[(f)->f_repeatcount])
#define	BACKOFF(f)	{ if (++(f)->f_repeatcount > MAXREPEAT) \
				 (f)->f_repeatcount = MAXREPEAT; \
			}

/** values for f_type */
#define F_UNUSED	0		/* unused entry */
#define F_FILE		1		/* regular file */
#define F_TTY		2		/* terminal */
#define F_CONSOLE	3		/* console terminal */
#define F_FORW		4		/* remote machine */
#define F_USERS		5		/* list of users */
#define F_WALL		6		/* everyone logged on */
#define	F_PIPE		7		/* pipe to program */

/*!
 * This structure represents the files that will have log
 * copies printed.
 * We require f_file to be valid if f_type is F_FILE, F_CONSOLE, F_TTY,
 * or if f_type is F_PIPE and f_pid > 0.
 */
struct filed {
	struct	filed *f_next;		/**< next in linked list */
	short	f_type;			/**< entry type, see below */
	short	f_file;			/**< file descriptor */
	time_t	f_time;			/**< time this was last written */
	char	*f_host;		/**< host from which to record */
	u_char	f_pmask[LOG_NFACILITIES+1];	/**< priority mask */
	u_char	f_pcmp[LOG_NFACILITIES+1];	/**< compare priority */
#define	PRI_LT	0x1
#define	PRI_EQ	0x2
#define	PRI_GT	0x4
	char	*f_program;		/**< program this applies to */
	union {
		char	f_uname[MAXUNAMES][UT_NAMESIZE+1];
		struct {
			char	f_hname[MAXHOSTNAMELEN];
			struct	addrinfo *f_addr;
		} f_forw;		/**< forwarding address */
		char	f_fname[MAXPATHLEN];
		struct {
			char	f_pname[MAXPATHLEN];
			pid_t	f_pid;
		} f_pipe;
	} f_un;
	char	f_prevline[MAXSVLINE];		/**< last message logged */
	char	f_lasttime[16];			/**< time of last occurrence */
	char	f_prevhost[MAXHOSTNAMELEN];	/**< host from which recd. */
	int	f_prevpri;			/**< pri of f_prevline */
	int	f_prevlen;			/**< length of f_prevline */
	int	f_prevcount;			/**< repetition cnt of prevline */
	int	f_repeatcount;			/**< number of "repeated" msgs */
	int	f_lasterror;			/**< last error on writev() */
	int	f_flags;			/**< file-specific flags */
#define	FFLAG_SYNC	0x01
};

/*!
 * Simple Message containing all needed for creating message.
 */
typedef struct msg {
	/*!
	 * These values are gathered during parsing of message
	 * @see printlog()
	 * @see logmsg()
	 */
	int  pri; /**< Message Priority value */
	char *timestamp; /**< Message Timestamp */
	char *hostname;  /**< Message authors hostname */
	char *app_name;  /**< Application originator name */
	syslog_pid_t pid;     /**< Application pid */
	syslog_msg_t msg_id;  /**< Message id */
	
	/*!
	 * These value are created by syslog_msg routines and
	 * are used to create major parts of message.
	 * @see syslog_msg_line_create()
	 * @see syslog_msg_sd_create()
	 * @see syslog_msg_header_create()
	 * @see logmsg()
	 */
	char *header; /**< Syslog Message header */
	char *sd;     /**< SD elements for this message*/
	char *line;   /**< Message text received from syslog source*/

	/** Message hash created from whole message before logging */
	char hash[SHA256_DIGEST_STRING_LENGTH];   /**< Message SHA256 hash */
	TAILQ_ENTRY(msg) next;
} msg_t;

TAILQ_HEAD(msg_queue_head, msg);

/*!
 * Message queue for messages I have to use own queue for every
 * SG -> Signature Group;
 */
typedef struct msg_queue {
	syslog_sg_t sg_id; /**< Signature Group id */
	size_t queue_size; /**< Size of message queue, when queue is full I have to sent hash msg */
	size_t msgs; /**< Current number of mesages in queue */
	struct msg_queue_head msg_queue; /**< Head of message */
	
	SLIST_ENTRY(msg_queue) next;
} msg_queue_t;

/* msg.c */
/** Add Message to message queue identified by signature id*/
int syslog_msg_queue_add(syslog_sg_t, msg_t *);

/** Inititalize message queue list header */
void syslog_msg_queue_init(void);

/** Initialize Message queue for Signature group */
int syslog_msg_queue_create(size_t, syslog_sg_t);

/** Destroy message queue*/
int syslog_msg_queue_destroy(syslog_sg_t);

msg_t *syslog_msg_create();
void syslog_msg_destroy(msg_t *);

void syslog_msg_set_header(char*, msg_t *);
void syslog_msg_set_line(char*, msg_t *);
void syslog_msg_set_sd(char*, msg_t *);
void syslog_msg_set_hash(char*, msg_t *);

char *syslog_msg_header_create(int, char*, char*, char*, syslog_pid_t, syslog_msg_t);
char *syslog_msg_sd_create();
char *syslog_msg_message_create(msg_t *);

/* sign.c */
int syslog_ssl_init();
int syslog_sign_init();
int syslog_sha1_msg(msg_t *, char *, size_t);
char *syslog_sign_buf(const char *, size_t);
char *syslog_sign_msg_create(struct msg_queue_head *);

#endif
