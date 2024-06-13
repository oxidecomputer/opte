/*
 * Track bad packets as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-bad-packet.d
 */
#include "common.h"

#define	HDR_FMT		"%-12s %-3s %-18s %s\n"
#define	LINE_FMT	"%-12s %-3s 0x%-16p %s[%d, %d]\n"

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
	this->res = stringof("");

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "DIR", "MBLK", "MSG+DATA");
		num = 0;
	}

	num++;
}

/* We can probably roll this out with clever macro use. */

bad-packet
/this->msg_len > 0/
{
	this->res = strjoin(this->res, stringof(this->msgs->entry[0]));
}

bad-packet
/this->msg_len > 1/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[1]));
}

bad-packet
/this->msg_len > 2/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[2]));
}

bad-packet
/this->msg_len > 3/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[3]));
}

bad-packet
/this->msg_len > 4/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[4]));
}

bad-packet
/this->msg_len > 5/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[5]));
}

bad-packet
/this->msg_len > 6/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[6]));
}

bad-packet
/this->msg_len > 7/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[7]));
}

bad-packet {
	printf(LINE_FMT,
		this->port, this->dir, this->mblk,
		this->res, this->msgs->data[0], this->msgs->data[1]
	);
}
