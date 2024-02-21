/*
 * Build histograms of packet tx/rx time spent within XDE's Mac callbacks.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-ht.d
 */
#include "common.h"
#include "protos.d"

#define	HDR_FMT "%-3s %-12s %-12s %-40s %-40s\n"

xde_mc_tx:entry {
	self->ts = vtimestamp;
}

xde_rx:entry {
	self->ts = vtimestamp;
}

xde_mc_tx:return /self->ts/ {
	@time["tx"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->ts = 0;
}

xde_rx:return /self->ts/ {
	@time["rx"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->ts = 0;
}

END {

}
