/*
 * Track flow expiration.
 *
 * dtrace -ZCqs ./usdt-opte-flow-expire.d
 */
#define	HDR_FMT "%-24s %-18s %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "FT NAME", "FLOW", "LAST_HIT", "NOW");
	num = 0;
}

flow-expired {
	this->port = copyinstr(arg0);
	this->layer = copyinstr(arg1);
	this->flow = copyinstr(arg2);
	this->last_hit = stringof(arg3);
	this->now = stringof(arg4);

	printf(HDR_FMT, this->port, this->layer, this->flow, this->last_hit, this->now);
}
