#define	HDR_FMT		"%-3s %-12s %-8s %-43s %-18s %s\n"
#define	LINE_FMT	"%-3s %-12s %-8u %-43s 0x%-16p %s\n"

BEGIN {
	printf(HDR_FMT, "DIR", "NAME", "EPOCH", "FLOW", "MBLK", "RESULT");
	num = 0;
}

port-process-return {
	this->dir = json(copyinstr(arg0), "ok");
	this->name = copyinstr(arg1);
	this->flow = copyinstr(arg2);
	this->epoch = arg3;
	this->mp = arg4;
	this->res = copyinstr(arg5);
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "DIR", "NAME", "EPCOH", "FLOW", "MBLK",
		    "RESULT");
		num = 0;
	}

	printf(LINE_FMT, this->dir, this->name, this->epoch, this->flow,
	    this->mp, this->res);
}
