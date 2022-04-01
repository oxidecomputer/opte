/*
 * Track flow expiration.
 *
 * dtrace -ZCqs ./usdt-opte-flow-expire.d
 */
#define	HDR_FMT "%-24s %-18s %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "FT NAME", "FLOW");
	num = 0;
}

flow-expired {
	this->port = copyinstr(arg0);
	this->layer = copyinstr(arg1);
	this->flow = copyinstr(arg2);

	printf(HDR_FMT, this->port, this->layer, this->flow);
}
