/*
 * Track rule match/no-match as it happens.
 *
 * dtrace -Cqs ./opte-rule-match.d
 */
#include <sys/inttypes.h>

typedef struct flow_id_sdt_arg {
	uint32_t	src_ip;
	uint32_t	dst_ip;
	uint16_t	src_port;
	uint16_t	dst_port;
	uint8_t		proto;
} flow_id_sdt_arg_t;

typedef struct rule_match_sdt_arg {
	char			*layer;
	char			*dir;
	flow_id_sdt_arg_t	*flow_id;
	char			*rule_type;
} rule_match_sdt_arg_t;

typedef struct rule_no_match_sdt_arg {
	char			*layer;
	char			*dir;
	flow_id_sdt_arg_t	*flow_id;
} rule_no_match_sdt_arg_t;


BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
}

rule-match {
	this->match = (rule_match_sdt_arg_t*)arg0;
	this->flow_id = this->match->flow_id;
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->src_ip = (ipaddr_t *)alloca(4);
	this->dst_ip = (ipaddr_t *)alloca(4);
	*this->src_ip = this->flow_id->src_ip;
	*this->dst_ip = this->flow_id->dst_ip;

	printf("MATCH %s %s (%s,%s:%u,%s:%u) => %s\n",
	    stringof(this->match->layer), stringof(this->match->dir),
	    protos[this->flow_id->proto],
	    inet_ntoa(this->src_ip), ntohs(this->flow_id->src_port),
	    inet_ntoa(this->dst_ip), ntohs(this->flow_id->dst_port),
	    stringof(this->match->rule_type));
}

rule-no-match {
	this->no_match = (rule_no_match_sdt_arg_t*)arg0;
	this->flow_id = this->no_match->flow_id;
	/*
	 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
	 * up the actual 32-bit IP value. You can't take the address
	 * of a dynamic variable, so make local allocations to
	 * reference.
	 */
	this->src_ip = (ipaddr_t *)alloca(4);
	this->dst_ip = (ipaddr_t *)alloca(4);
	*this->src_ip = this->flow_id->src_ip;
	*this->dst_ip = this->flow_id->dst_ip;

	printf("NO_MATCH %s %s (%s,%s:%u,%s:%u)\n",
	    stringof(this->no_match->layer), stringof(this->no_match->dir),
	    protos[this->flow_id->proto],
	    inet_ntoa(this->src_ip), ntohs(this->flow_id->src_port),
	    inet_ntoa(this->dst_ip), ntohs(this->flow_id->dst_port));
}
