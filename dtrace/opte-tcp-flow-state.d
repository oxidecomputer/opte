/*
 * Track TCP flows as they change state.
 *
 * dtrace -Cqs ./opte-tcp-flow-state.d
 */
#include <sys/inttypes.h>

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
	 * Use an associative array to stringify the TCP state
	 * values.
	 */
	tcp_states[0] = "CLOSED";
	tcp_states[1] = "LISTEN";
	tcp_states[2] = "SYN_SENT";
	tcp_states[3] = "SYN_RCVD";
	tcp_states[4] = "ESTABLISHED";
	tcp_states[5] = "CLOSE_WAIT";
	tcp_states[6] = "LAST_ACK";
	tcp_states[7] = "FIN_WAIT_1";
	tcp_states[8] = "FIN_WAIT_2";
	tcp_states[9] = "TIME_WAIT";
}

tcp-flow-state {
	this->flow_id = (flow_id_sdt_arg_t *)arg0;
	this->af = this->flow_id->af;
}

tcp-flow-state /this->af == AF_INET/ {
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->src_ip = (ipaddr_t *)alloca(4);
	this->dst_ip = (ipaddr_t *)alloca(4);
	*this->src_ip = this->flow_id->src_ip4;
	*this->dst_ip = this->flow_id->dst_ip4;

	printf("%16s -> %-16s %s:%u %s:%u\n", tcp_states[arg1],
	    tcp_states[arg2], inet_ntoa(this->src_ip), this->flow_id->src_port,
	    inet_ntoa(this->dst_ip), this->flow_id->dst_port);
}

tcp-flow-state /this->af == AF_INET6/ {
	this->src_ip6 = (in6_addr_t *)alloca(16);
	this->dst_ip6 = (in6_addr_t *)alloca(16);
	*this->src_ip6 = this->flow_id->src_ip6;
	*this->dst_ip6 = this->flow_id->dst_ip6;

	printf("%16s -> %-16s %s:%u %s:%u\n", tcp_states[arg1],
	    tcp_states[arg2], inet_ntoa6(this->src_ip6),
	    this->flow_id->src_port, inet_ntoa6(this->dst_ip6),
	    this->flow_id->dst_port);
}
