/*
 * Track Header Transpositions as they happen.
 *
 * dtrace -Cqs ./opte-ht.d
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

typedef struct ht_run_sdt_arg {
	char			*loc;
	char			*dir;
	flow_id_sdt_arg_t	*flow_id_before;
	flow_id_sdt_arg_t	*flow_id_after;
} ht_run_sdt_arg_t;

#define	HDR_FMT "%-3s %-12s %-40s %-40s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1]= "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";

	printf(HDR_FMT, "DIR", "LOCATION", "BEFORE", "AFTER");
	num = 0;
}

ht-run {
	if (num >= 10) {
		printf(HDR_FMT, "DIR", "LOCATION", "BEFORE", "AFTER");
		num = 0;
	}

	this->ht = (ht_run_sdt_arg_t*)arg0;
	this->before = this->ht->flow_id_before;
	this->after = this->ht->flow_id_after;
	this->af = this->before->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

ht-run /this->af == AF_INET/ {
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->b_src_ip = (ipaddr_t *)alloca(4);
	this->b_dst_ip = (ipaddr_t *)alloca(4);
	*this->b_src_ip = this->before->src_ip4;
	*this->b_dst_ip = this->before->dst_ip4;
	this->a_src_ip = (ipaddr_t *)alloca(4);
	this->a_dst_ip = (ipaddr_t *)alloca(4);
	*this->a_src_ip = this->after->src_ip4;
	*this->a_dst_ip = this->after->dst_ip4;


	printf("%-3s %-12s %s,%s:%u,%s:%u\t%s,%s:%u,%s:%u\n",
	    stringof(this->ht->dir),
	    stringof(this->ht->loc),
	    protos[this->before->proto],
	    inet_ntoa(this->b_src_ip), ntohs(this->before->src_port),
	    inet_ntoa(this->b_dst_ip), ntohs(this->before->dst_port),
	    protos[this->after->proto],
	    inet_ntoa(this->a_src_ip), ntohs(this->after->src_port),
	    inet_ntoa(this->a_dst_ip), ntohs(this->after->dst_port));

	num++;
}

ht-run /this->af == AF_INET6/ {
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->b_src_ip6 = (in6_addr_t *)alloca(16);
	this->b_dst_ip6 = (in6_addr_t *)alloca(16);
	*this->b_src_ip6 = this->before->src_ip6;
	*this->b_dst_ip6 = this->before->dst_ip6;
	this->a_src_ip6 = (in6_addr_t *)alloca(16);
	this->a_dst_ip6 = (in6_addr_t *)alloca(16);
	*this->a_src_ip6 = this->after->src_ip6;
	*this->a_dst_ip6 = this->after->dst_ip6;


	printf("%-3s %-12s %s,%s:%u,%s:%u\t%s,%s:%u,%s:%u\n",
	    stringof(this->ht->dir),
	    stringof(this->ht->loc),
	    protos[this->before->proto],
	    inet_ntoa6(this->b_src_ip6), ntohs(this->before->src_port),
	    inet_ntoa6(this->b_dst_ip6), ntohs(this->before->dst_port),
	    protos[this->after->proto],
	    inet_ntoa6(this->a_src_ip6), ntohs(this->after->src_port),
	    inet_ntoa6(this->a_dst_ip6), ntohs(this->after->dst_port));

	num++;
}
