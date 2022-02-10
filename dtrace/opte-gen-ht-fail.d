/*
 * Track StaticAction::gen_ht() failures.
 *
 * dtrace -Cqs ./opte-gen-desc-fail.d
 */
typedef struct flow_id_sdt_arg {
	int		af;
	ipaddr_t	src_ip4;
	ipaddr_t	dst_ip4;
	in6_addr_t	src_ip6;
	in6_addr_t	dst_ip6;
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

gen-ht-fail {
	this->port = stringof(arg0);
	this->layer = stringof(arg1);
	this->dir = stringof(arg2);
	this->flow_id = (flow_id_sdt_arg_t *)arg3;
	this->msg = stringof(arg4);
	this->af = this->flow_id->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

gen-ht-fail /this->af == AF_INET/ {
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->srcp = (ipaddr_t *)alloca(4);
	this->dstp = (ipaddr_t *)alloca(4);
	*this->srcp = this->flow_id->src_ip4;
	*this->dstp = this->flow_id->dst_ip4;
	this->srcps = inet_ntoa(this->srcp);
	this->dstps = inet_ntoa(this->dstp);

	printf("%s:%s %s %s %s:%u %s:%u %s\n", this->port, this->layer,
	    this->dir, protos[this->flow_id->proto], this->srcps,
	    this->flow_id->src_port, this->dstps, this->flow_id->dst_port,
	    this->msg);
}

gen-ht-fail /this->af == AF_INET6/ {
	this->srcp6 = (in6_addr_t *)alloca(16);
	this->dstp6 = (in6_addr_t *)alloca(16);
	*this->srcp6 = this->flow_id->src_ip6;
	*this->dstp6 = this->flow_id->dst_ip6;
	this->srcps6 = inet_ntoa6(this->srcp6);
	this->dstps6 = inet_ntoa6(this->dstp6);

	printf("%s:%s %s %s %s:%u %s:%u %s\n", this->port, this->layer,
	    this->dir, protos[this->flow_id->proto], this->srcps6,
	    this->flow_id->src_port, this->dstps6, this->flow_id->dst_port,
	    this->msg);
}
