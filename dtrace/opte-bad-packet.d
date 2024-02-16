/*
 * Track bad packets as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-bad-packet.d
 */
#include "common.h"

#define	HDR_FMT		"%-12s %-3s %-18s %s\n"
#define	LINE_FMT	"%-12s %-3s 0x%-16p "
#define	EL_FMT		"->%s"

BEGIN {
	printf(HDR_FMT, "PORT", "DIR", "MBLK", "MSG+DATA");
	num = 0;
}

bad-packet {
	this->port = stringof(arg0);
	this->dir = DIR_STR(arg1);
	this->mblk = arg2;
	this->msgs = (char**) arg3;
	this->msg_len = arg4;
	this->truncated = arg5;
	this->data = (uint64_t*) arg6;
	this->data_len = arg7;

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "DIR", "MBLK", "MSG+DATA");
		num = 0;
	}

	printf(LINE_FMT, this->port, this->dir, this->mblk);
	num++;
}

/* We can probably roll this out with clever macro use. */

bad-packet
/this->msg_len > 0/
{
	printf("%s", stringof(this->msgs[0]));
}

bad-packet
/this->msg_len > 1/
{
	printf(EL_FMT, stringof(this->msgs[1]));
}

bad-packet
/this->msg_len > 2/
{
	printf(EL_FMT, stringof(this->msgs[2]));
}

bad-packet
/this->msg_len > 3/
{
	printf(EL_FMT, stringof(this->msgs[3]));
}

bad-packet {
	printf(" [%d, %d]\n", this->data[0], this->data[1]);
}
