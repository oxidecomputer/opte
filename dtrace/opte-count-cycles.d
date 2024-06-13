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

END {

}