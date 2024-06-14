worker-pkt-start {
	self->ts = vtimestamp;
	self->dir = arg0;
}

worker-pkt-end /self->dir == 1 && self->ts/ {
	@time["rx"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
}

worker-pkt-end /self->dir == 2 && self->ts/ {
	@time["tx"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
}

worker-pkt-end {
	self->ts = 0;
	self->dir = 0;
}

xde_rx:entry {
	self->drop_time = vtimestamp;
}

xde_mc_tx:entry {
	self->drop_time = vtimestamp;
}

xde_rx:return /self->dir/ {
	@time["place_in_inner"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->drop_time = 0;
}

xde_mc_tx:return /self->dir/ {
	@time["place_out_inner"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->drop_time = 0;
}

xde_rx:return /!self->dir/ {
	@time["place_in"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->drop_time = 0;
}

xde_mc_tx:return /!self->dir/ {
	@time["place_out"] = lquantize((vtimestamp - self->ts), 256, 32768, 256);
	self->drop_time = 0;
}

xde_rx:return {
	self->drop_time = 0;
}

xde_mc_tx:return {
	self->drop_time = 0;
}

END {

}