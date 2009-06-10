#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "syslogd.h"

SLIST_HEAD(msg_queue_list_head, msg_queue);

/** SLIST HEAD of all msg lists created per every SG group */
static struct msg_queue_list_head msg_list_head;

static syslog_msg_t msg_counter;

extern Debug;

static msg_queue_t * msg_queue_find_sgid(syslog_sg_t);
static void msg_queue_dump(struct msg_queue_head *msg_head);


static void
msg_queue_dump(struct msg_queue_head *msg_head)
{
	msg_t *msg;

	dprintf("-----------------------------------------\n");
	dprintf("Messages in queue:\n");
	TAILQ_FOREACH(msg, msg_head, next){
		dprintf("%s %s %s\n", msg->header, msg->sd, msg->line);
		dprintf("\t%s\n", msg->hash);
	}
	dprintf("-----------------------------------------\n");
}

/** Search for Signature Group ID in a msg list. */
static msg_queue_t *
msg_queue_find_sgid(syslog_sg_t sg_id)
{
	msg_queue_t *msgq;
	
	SLIST_FOREACH(msgq, &msg_list_head, next) {
		if (sg_id == msgq->sg_id)
			return msgq;
	}

	return 0;
}

/*!
 * Add Message to message queue identified by signature id
 * @param sg_id Signature Group ID
 * @param msg poiter to msg description structure
 * @bug Free all messages in msg_t::msg_queue after sending hash msg
 * @bug Implement sending message with hashes.
 * @see logmsg()
 */
int
syslog_msg_queue_add(syslog_sg_t sg_id, msg_t *msg)
{
	msg_queue_t *msgq;

	assert (msg != NULL);

	if ((msgq = msg_queue_find_sgid(sg_id)) == NULL)
		return ENOENT;

	TAILQ_INSERT_TAIL(&msgq->msg_queue, msg, next);

	msgq->msgs++;

	msg_queue_dump(&msgq->msg_queue);
	
	if (msgq->msgs == msgq->queue_size) {
		dprintf("Sending hash message SG %d\n", sg_id);
		syslog_sign_msg_create(&msgq->msg_queue);
		msgq->msgs = 0;
		/* initialize message queue to NULL after removing all msgs from it */
		TAILQ_INIT(&msgq->msg_queue);
	}
	return 0;
}

/** Initialize message queue head */
void
syslog_msg_queue_init(void)
{
	SLIST_INIT(&msg_list_head);
}
	
/*!
 * Initialize message queue for size and SG.
 * @param size Size of message queue, when mesage queue is full message with hashes is sent.
 * @param sg_id Signature Group ID.
 */
int
syslog_msg_queue_create(size_t size, syslog_sg_t sg_id)
{
	msg_queue_t *msgq;
	
	assert(size > 0);

	dprintf("!!! Creating MEssage queue for SG %d with size %d\n", sg_id, size);
	msgq = malloc(sizeof(msg_queue_t));

	msgq->sg_id = sg_id;
	msgq->queue_size = size;
	msgq->msgs = 0;

	TAILQ_INIT(&msgq->msg_queue);

	SLIST_INSERT_HEAD(&msg_list_head, msgq, next);
	
	return 0;
}

/*!
 * Destroy message queue selected with sg_id
 * @bug Destroy all msgs in msg_t::mds_queue when freeing this struct.
 */
int
syslog_msg_queue_destroy(syslog_sg_t sg_id)
{
	msg_queue_t *msgq;

	/* Find message queue by signature ID */
	msgq = msg_queue_find_sgid(sg_id);

	if (msgq == NULL)
		return ENOENT;

	/* I have to desotry all message in a queue when I'm removing sg msg queue */
	if (!TAILQ_EMPTY(&msgq->msg_queue))
		return EBUSY;
	
	free(msgq);
	
	return 0;
}

/*********************************************************************************
 * Message creating functions
 *********************************************************************************/
/*!
 * Allocate Message
 */
msg_t *
syslog_msg_create()
{
	msg_t *msg;

	if ((msg = malloc(sizeof(msg_t))) == NULL)
		return NULL;

	memset(msg, '0', sizeof(msg_t));

	msg->header = NULL;
	msg->line = NULL;
	msg->sd = NULL;
	msg->msg_id = msg_counter++;
	
	return msg;
}

/*!
 * Destroy message, before this message must be removed from all
 * msg lists.
 * @see syslog_msg_queue_add()
 * @see syslog_msg_queue_destroy()
 */
void
syslog_msg_destroy(msg_t *msg)
{
	assert (msg != NULL);
	
	if (msg->header != NULL)
		free(msg->header);

	if (msg->line != NULL)
		free(msg->line);

	if (msg->sd != NULL)
		free(msg->sd);

	if (msg->hash != NULL)
		free(msg->hash);
}

/** Set message header */
void
syslog_msg_set_header(char *header, msg_t *msg)
{
	assert(msg != NULL);
	if (msg->header != NULL)
		free(msg->header);
	
	msg->header = header;
}

/** Set message line/text */
void
syslog_msg_set_line(char *line, msg_t *msg)
{
	assert(msg != NULL);
	if (msg->line != NULL)
		free(msg->line);
	
	msg->line = line;
}

/** Set message sd elements */
void
syslog_msg_set_sd(char *sd, msg_t *msg)
{
	assert(msg != NULL);
	if (msg->sd != NULL)
		free(msg->sd);

	msg->sd = sd;
}

/** Set message hash */
void
syslog_msg_set_hash(char *hash, msg_t *msg)
{
	assert(msg != NULL);

	strncpy(msg->hash, hash, sizeof(msg->hash));
}

/*!
 * Alloc message header
 * @param pri Priority value
 * @param hostname Name/IP address of logger
 * @param times Timestamp when was message created
 * @param app_name Name of Aplication which created this message
 * @param proc_id Pid or other process identificator
 * @param msg_id Message id -> it is message counter.
 * @see logmsg()
 * @bug this interface is broken probably it need some more work
 */
char *
syslog_msg_header_create(int pri, char *hostname, char *times,
    char *app_name, syslog_pid_t proc_id, syslog_msg_t msg_id)
{
	char *header;
	char *proc, *msgid;
	size_t size;
	
	if (proc_id < 0)
		asprintf(&proc, "-");
	else
		asprintf(&proc, "%d", proc_id);

	if (msg_id < 0)
		asprintf(&msgid, "%"PRIu64, msg_counter++);
	else
		asprintf(&msgid, "%"PRIu64, msg_id);
	
	size = asprintf(&header, "<%d>%d %s %s %s %s %s", pri, SYSLOG_VERSION, times,
	    hostname, app_name, proc, msgid);

	dprintf("Message header: %s\n", header);

	free(proc);
	free(msgid);
	
	return header;
}

/*!
 * Alloc SD elements string for msg.
 * @bug Add normal support for SD elements
 */
char *
syslog_msg_sd_create()
{
	char *sde;
	asprintf(&sde,"[exampleSDID@]");
	dprintf("Created sd elements: %s\n", sde);
	return sde;
}

char *
syslog_msg_message_create(msg_t *msg)
{
	char *msg_buf;
	dprintf("%s %s %s\n", msg->header, msg->sd, msg->line);
	asprintf(&msg_buf,"%s %s %s", msg->header, msg->sd, msg->line);
	syslog_sha1_msg(msg, msg_buf, strlen(msg_buf));
	dprintf("Message: %s\n", msg_buf);
	dprintf("Hash: %s\n", msg->hash);
	return msg_buf;
}
