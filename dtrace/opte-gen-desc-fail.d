/*
 * Track gen_desc() failures for stateful actions.
 *
 * dtrace -Cqs ./opte-gen-desc-fail.d
 */
typedef struct flow_id_sdt_arg {
	uint32_t	src_ip;
	uint32_t	dst_ip;
	uint16_t	src_port;
	uint16_t	dst_port;
	uint8_t		proto;
} flow_id_sdt_arg_t;

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
}

gen-desc-fail {
	this->port = stringof(arg0);
	this->layer = stringof(arg1);
	this->dir = stringof(arg2);
	this->flow_id = (flow_id_sdt_arg_t *)arg3;
	this->msg = stringof(arg4);

	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->srcp = (ipaddr_t *)alloca(4);
	this->dstp = (ipaddr_t *)alloca(4);
	*this->srcp = this->flow_id->src_ip;
	*this->dstp = this->flow_id->dst_ip;

	printf("%s:%s %s %s %s:%u %s:%u %s\n", this->port, this->layer,
	    this->dir, protos[this->flow_id->proto], inet_ntoa(this->srcp),
	    this->flow_id->src_port, inet_ntoa(this->dstp),
	    this->flow_id->dst_port, this->msg);
}
