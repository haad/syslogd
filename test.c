#include <sys/param.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>


int
main(int argc,char  *argv[]){

	syslog(LOG_ERR, "TESTING SYSLOG DAEMON");

	return 0;


}
