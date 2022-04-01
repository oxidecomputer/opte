/*
 * Track rule match/no-match as it happens. This is the USDT version;
 * useful for debugging when running tests.
 *
 * dtrace -ZCqs ./usdt-opte-rule-match.d
 */
#define	HDR_FMT		"%-8s %-12s %-6s %-3s %-43s %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "LAYER", "MATCH", "DIR", "FLOW", "ACTION");
	num = 0;
}

rule-match {
	this->port = copyinstr(arg0);
	this->layer = copyinstr(arg1);
	this->dir = json(copyinstr(arg2), "ok");
	this->flow = copyinstr(arg3);
	this->action = copyinstr(arg4);

	printf(HDR_FMT, this->port, this->layer, "YES", this->dir, this->flow,
	    this->action);
}

rule-no-match {
	this->port = copyinstr(arg0);
	this->layer = copyinstr(arg1);
	this->dir = json(copyinstr(arg2), "ok");
	this->flow = copyinstr(arg3);

	printf(HDR_FMT, this->port, this->layer, "NO", this->dir, this->flow,
	    "--");
}

rule-match,rule-no-match {
	if (num >= 10) {
		printf(HDR_FMT, "PORT", "LAYER", "MATCH", "DIR", "FLOW",
		    "ACTION");
		num = 0;
	}

	num++;
}
