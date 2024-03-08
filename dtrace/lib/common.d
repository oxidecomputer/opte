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
	uintptr_t		dir;
	flow_id_sdt_arg_t	*flow;
	char			*rule_type;
} rule_match_sdt_arg_t;

typedef struct rule_no_match_sdt_arg {
	char			*port;
	char			*layer;
	uintptr_t		dir;
	flow_id_sdt_arg_t	*flow;
} rule_no_match_sdt_arg_t;

typedef struct ht_run_sdt_arg {
	char			*port;
	char			*loc;
	uintptr_t		dir;
	flow_id_sdt_arg_t	*flow_before;
	flow_id_sdt_arg_t	*flow_after;
} ht_run_sdt_arg_t;

typedef struct opte_cmd_ioctl {
	uint64_t		api_version;
	int			cmd;
	uint64_t		flags;
	uint64_t		reserved;
	char			*req_bytes;
	size_t			req_len;
	char			*resp_bytes;
	size_t			resp_len;
	size_t			resp_len_actual;
} opte_cmd_ioctl_t;

typedef struct derror_sdt_arg {
    size_t len;
    uint8_t truncated;
    uint64_t data[2];
    char* entry[8];
} derror_sdt_arg_t;
