/*
 * Track layer processing.
 *
 * dtrace -ZCqs ./usdt-opte-layer-process.d
 */
#define	HDR_FMT "%-16s %-16s %-3s %-48s %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW", "RES");
	num = 0;
}

layer-process-return {
	this->dir = json(copyinstr(arg0), "ok");
	this->port = copyinstr(arg1);
	this->layer = copyinstr(arg2);
	this->flow = copyinstr(arg3);
	this->res = copyinstr(arg4);
	num++;

	printf(HDR_FMT, this->port, this->layer, this->dir, this->flow,
	    this->res);

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW", "RES");
		num = 0;
	}
}
