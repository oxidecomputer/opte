/*
 * Track TCP state changes.
 *
 * dtrace -ZCqs ./usdt-opte-tcp-flow-state.d
 */
#define	HDR_FMT "%-16s %-8s %-8s %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "CURR", "NEW", "FLOW");
	num = 0;
}

tcp-flow-state {
	this->port = copyinstr(arg0);
	this->flow = copyinstr(arg1);
	this->curr = copyinstr(arg2);
	this->new = copyinstr(arg3);
	num++;

	printf(HDR_FMT, this->port, this->curr, this->new, this->flow);

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "CURR", "NEW", "FLOW");
		num = 0;
	}
}
