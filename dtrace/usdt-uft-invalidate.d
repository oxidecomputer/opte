#define	HDR_FMT		"%-8s %-3s %-43s %s\n"
#define	LINE_FMT	"%-8s %-3s %-43s %u\n"

BEGIN {
	printf(HDR_FMT, "PORT", "DIR", "FLOW", "EPOCH");
	num = 0;
}

uft-invalidate {
	this->dir = json(copyinstr(arg0), "ok");
	this->port = copyinstr(arg1);
	this->flow = copyinstr(arg2);
	this->epoch = arg3;
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "DIR", "FLOW", "EPOCH");
		num = 0;
	}

	printf(LINE_FMT, this->port, this->dir, this->flow, this->epoch);
}
