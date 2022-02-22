/*
 * Track flow expiration.
 *
 * dtrace -Cqs ./opte-flow-expire.d
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

#define	HDR_FMT "%-12s %-40s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1]= "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";

	printf(HDR_FMT, "NAME", "FLOW");
	num = 0;
}

/* sdt:opte::flow-expired { */
/* } */

sdt:opte::flow-expired {
	this->name = stringof(arg0);
	this->flow = (flow_id_sdt_arg_t *)arg1;

	if (num >= 10) {
		printf(HDR_FMT, "NAME", "FLOW");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

sdt:opte::flow-expired /this->af == AF_INET/ {
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->src_ip = (ipaddr_t *)alloca(4);
	this->dst_ip = (ipaddr_t *)alloca(4);
	*this->src_ip = this->flow->src_ip4;
	*this->dst_ip = this->flow->dst_ip4;


	printf("%-12s %s,%s:%u,%s:%u\n",
	    this->name, protos[this->flow->proto], inet_ntoa(this->src_ip),
	    ntohs(this->flow->src_port), inet_ntoa(this->dst_ip),
	    ntohs(this->flow->dst_port));

	num++;
}

sdt:opte::flow-expired /this->af == AF_INET6/ {
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->src_ip6 = (in6_addr_t *)alloca(16);
	this->dst_ip6 = (in6_addr_t *)alloca(16);
	*this->src_ip6 = this->flow->src_ip6;
	*this->dst_ip6 = this->flow->dst_ip6;

	printf("%-12s %s,%s:%u,%s:%u\n",
	    this->name, protos[this->flow->proto], inet_ntoa6(this->src_ip6),
	    ntohs(this->flow->src_port), inet_ntoa6(this->dst_ip6),
	    ntohs(this->flow->dst_port));

	num++;
}

