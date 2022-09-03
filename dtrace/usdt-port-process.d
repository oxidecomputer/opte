#define	HDR_FMT		"%-3s %-12s %-8s %-43s %-43s %-18s %s\n"
#define	LINE_FMT	"%-3s %-12s %-8u %-43s %-43s 0x%-16p %s\n"

BEGIN {
	printf(HDR_FMT, "DIR", "NAME", "EPOCH", "FLOW BEFORE", "FLOW AFTER",
	    "MBLK", "RESULT");
	num = 0;
}

port-process-return {
	this->dir = json(copyinstr(arg0), "ok.0");
	this->name = json(copyinstr(arg0), "ok.1");
	this->flow_before = json(copyinstr(arg1), "ok.0");
	this->flow_after = json(copyinstr(arg1), "ok.1");
	this->epoch = arg2;
	this->mp = arg3;
	this->res = copyinstr(arg4);
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "DIR", "NAME", "EPCOH", "FLOW BEFORE",
		    "FLOW AFTER", "MBLK", "RESULT");
		num = 0;
	}

	printf(LINE_FMT, this->dir, this->name, this->epoch,
	    this->flow_before, this->flow_after, this->mp, this->res);
}
