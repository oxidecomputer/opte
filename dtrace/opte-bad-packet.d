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

bad-packet {
	this->port = stringof(arg0);
	this->dir = stringof(arg1);
	this->mblk = arg2;
	this->msg = stringof(arg3);

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "DIR", "MBLK", "MSG");
		num = 0;
	}

	printf(LINE_FMT, this->port, this->dir, this->mblk, this->msg);
	num++;
}
