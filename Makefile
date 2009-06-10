#	$NetBSD: Makefile,v 1.20 2007/05/28 12:06:42 tls Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/6/93
#./syslogd -p /var/run/log2 -dnv -u haad -f syslog.conf
.include <bsd.own.mk>

USE_FORT?= yes	# network server

PROG=	syslogd
SRCS=	syslogd.c utmpentry.c sign.c msg.c
MAN=	syslogd.8 syslog.conf.5
CFLAGS += -g
DPADD+=${LIBUTIL}
LDADD+=-lutil
LDADD+=-lssl -lcrypto
#make symlink to old socket location for transitional period
SYMLINKS=	/var/run/log /dev/log
.PATH.c: ${NETBSDSRCDIR}/usr.bin/who
CPPFLAGS+=-I${NETBSDSRCDIR}/usr.bin/who -DSUPPORT_UTMPX -DSUPPORT_UTMP

.if (${USE_INET6} != "no")
CPPFLAGS+=-DINET6
.endif

CPPFLAGS+=-DLIBWRAP
LDADD+=	-lwrap
DPADD+=	${LIBWRAP}

.include <bsd.prog.mk>
