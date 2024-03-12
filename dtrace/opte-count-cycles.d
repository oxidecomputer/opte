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
