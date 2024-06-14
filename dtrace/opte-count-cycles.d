xde_mc_tx:entry {
	self->tx_ts = vtimestamp;
}

xde_rx:entry {
	self->rx_ts = vtimestamp;
}

xde_mc_tx:return /self->tx_ts/ {
	@time["tx"] = lquantize((vtimestamp - self->tx_ts), 256, 32768, 256);
	self->tx_ts = 0;
}

xde_rx:return /self->rx_ts/ {
	@time["rx"] = lquantize((vtimestamp - self->rx_ts), 256, 32768, 256);
	self->rx_ts = 0;
}

END {

}
