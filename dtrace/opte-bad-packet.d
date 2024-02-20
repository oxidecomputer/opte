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
	this->msgs = (derror_sdt_arg_t*) arg3;
	this->msg_len = this->msgs->len;
	this->data_len = arg4;

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
	printf("%s", stringof(this->msgs->entry[0]));
}

bad-packet
/this->msg_len > 1/
{
	printf(EL_FMT, stringof(this->msgs->entry[1]));
}

bad-packet
/this->msg_len > 2/
{
	printf(EL_FMT, stringof(this->msgs->entry[2]));
}

bad-packet
/this->msg_len > 3/
{
	printf(EL_FMT, stringof(this->msgs->entry[3]));
}

bad-packet
/this->msg_len > 4/
{
	printf(EL_FMT, stringof(this->msgs->entry[4]));
}

bad-packet
/this->msg_len > 5/
{
	printf(EL_FMT, stringof(this->msgs->entry[5]));
}

bad-packet
/this->msg_len > 6/
{
	printf(EL_FMT, stringof(this->msgs->entry[6]));
}

bad-packet
/this->msg_len > 7/
{
	printf(EL_FMT, stringof(this->msgs->entry[7]));
}

bad-packet {
	printf(" [%d, %d]\n", this->msgs->data[0], this->msgs->data[1]);
}
