/*
 * Track bad packets as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-bad-packet.d
 */
#include "common.h"

#define	HDR_FMT		"%-12s %-3s %-18s %s\n"
#define	LINE_FMT	"%-12s %-3s 0x%-16p %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "DIR", "MBLK", "MSG");
	num = 0;
}

tcp-err {
	this->dir = DIR_STR(arg0);
	this->port = stringof(arg1);
	this->flow_id = stringof(arg2);
	this->mblk = arg3;
	this->msg = stringof(arg4);

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "DIR", "MBLK", "MSG");
		num = 0;
	}

	printf(LINE_FMT, this->port, this->dir, this->mblk, this->msg);
	stack();
	num++;
}
