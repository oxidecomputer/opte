#pragma D depends_on module ip
#pragma D depends_on provider ip

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

typedef struct rule_match_sdt_arg {
	char			*port;
	char			*layer;
	char			*dir;
	flow_id_sdt_arg_t	*flow;
	char			*rule_type;
} rule_match_sdt_arg_t;

typedef struct rule_no_match_sdt_arg {
	char			*port;
	char			*layer;
	char			*dir;
	flow_id_sdt_arg_t	*flow;
} rule_no_match_sdt_arg_t;

typedef struct ht_run_sdt_arg {
	char			*port;
	char			*loc;
	char			*dir;
	flow_id_sdt_arg_t	*flow_before;
	flow_id_sdt_arg_t	*flow_after;
} ht_run_sdt_arg_t;
