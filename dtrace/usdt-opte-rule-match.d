/*
 * Track rule match/no-match as it happens. This is the USDT version;
 * useful for debugging when running tests.
 *
 * dtrace -ZCqs ./usdt-opte-rule-match.d
 */
#define	HDR_FMT		"%-6s %-3s %-12s %-43s %s\n"

BEGIN {
	printf(HDR_FMT, "MATCH", "DIR", "LAYER", "FLOW", "ACTION");
	num = 0;
}

rule-match {
	this->layer = copyinstr(arg0);
	this->dir = json(copyinstr(arg1), "ok");
	this->flow = copyinstr(arg2);
	this->action = copyinstr(arg3);
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "MATCH", "DIR", "LAYER", "FLOW", "ACTION");
		num = 0;
	}

	printf(HDR_FMT, "YES", this->dir, this->layer, this->flow,
	    this->action);
}

rule-no-match {
	this->layer = copyinstr(arg0);
	this->dir = json(copyinstr(arg1), "ok");
	this->flow = copyinstr(arg2);
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "MATCH", "DIR", "LAYER", "FLOW", "ACTION");
		num = 0;
	}

	printf(HDR_FMT, "NO", this->dir, this->layer, this->flow, "--");
}
