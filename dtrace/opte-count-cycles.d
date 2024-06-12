xde_mc_tx:entry {
	self->ts = vtimestamp;
}

xde_rx:entry {
	self->ts = vtimestamp;
}

xde_mc_tx_one:return /self->ts/ {
	@time["tx"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->ts = 0;
}

xde_rx_one:return /self->ts/ {
	@time["rx"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->ts = 0;
}

END {

}
