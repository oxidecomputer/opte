#define	HDR_FMT		"%-3s %-12s %-43s 0x%-16s %s\n"
#define	LINE_FMT	"%-3s %-12s %-43s 0x%-16p %s\n"

BEGIN {
	printf(HDR_FMT, "DIR", "NAME", "FLOW", "MBLK", "RESULT");
	num = 0;
}

port-process-return {
	this->dir = json(copyinstr(arg0), "ok");
	this->name = copyinstr(arg1);
	this->flow = copyinstr(arg2);
	this->mp = arg3;
	this->res = copyinstr(arg4);
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "DIR", "NAME", "FLOW", "MBLK", "RESULT");
		num = 0;
	}

	printf(LINE_FMT, this->dir, this->name, this->flow, this->mp, this->res);
}