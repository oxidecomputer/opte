/*
 * Track layer processing.
 *
 * dtrace -ZCqs ./usdt-opte-layer-process.d
 */
#define	HDR_FMT "%-16s %-16s %-3s %-48s %-48s %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW BEFORE", "FLOW AFTER",
	    "RES");
	num = 0;
}

layer-process-return {
	this->dir = json(copyinstr(arg0), "ok.0");
	this->port = json(copyinstr(arg0), "ok.1");
	this->layer = copyinstr(arg1);
	this->flow_before = copyinstr(arg2);
	this->flow_after = copyinstr(arg3);
	this->res = copyinstr(arg4);
	num++;

	printf(HDR_FMT, this->port, this->layer, this->dir, this->flow_before,
	    this->flow_after, this->res);

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW BEFORE",
		    "FLOW AFTER", "RES");
		num = 0;
	}
}
