/*
 * Track TCP flow drops. These occur when either the packet doesn't
 * match the current expected state in the TCP state machine or when
 * the connection is CLOSED.
 *
 * dtrace -ZCqs ./usdt-opte-tcp-flow-drop.d
 */
#define	HDR_FMT "%-16s %-48s %-24s %-8s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "FLOW", "STATE", "FLAGS");
	num = 0;
}

tcp-flow-drop {
	this->port = copyinstr(arg0);
	this->flow = copyinstr(arg1);
	this->state = copyinstr(arg2);
	this->flags = copyinstr(arg3);
	num++;

	printf(HDR_FMT, this->port, this->flow, this->state, this->flags);

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "FLOW", "STATE", "FLAGS");
		num = 0;
	}
}
