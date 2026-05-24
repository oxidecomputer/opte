/*
 * Route cache latency benchmark.
 *
 * Instruments RouteCache::next_hop via FBT entry/return to measure
 * per-lookup latency, classified by cache outcome (hit, insert,
 * refresh, full) using SDT probes.
 *
 * Uses quantize() for wide bucket coverage since lookup latency
 * spans from ~256ns (cache hit) to >1ms (cache full under
 * contention).
 *
 * dtrace -s ./opte-routecache-bench.d
 */

fbt:xde:*RouteCache*next_hop*:entry
{
	self->ts = timestamp;
	self->evt = "hit";
}

sdt:xde::routecache-refresh { self->evt = "refresh"; }
sdt:xde::routecache-insert  { self->evt = "insert"; }
sdt:xde::routecache-full    { self->evt = "full"; }

fbt:xde:*RouteCache*next_hop*:return
/self->ts && self->evt != NULL/
{
	@time[self->evt] = quantize(timestamp - self->ts);
	@count_rc[self->evt] = count();
	self->ts = 0;
}

END
{
	printa(@count_rc);
}
