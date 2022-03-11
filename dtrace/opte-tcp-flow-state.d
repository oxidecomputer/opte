/*
 * Track TCP flows as they change state.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-tcp-flow-state.d
 */
#include "common.h"

#define	FMT	"%-16s %-16s %s"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 * It's always going to be TCP but we need this declared so
	 * the FLOW_FMT macros work.
	 */
	protos[1]= "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";

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
	this->flow = (flow_id_sdt_arg_t *)arg0;
	this->af = this->flow->af;
	this->bstate = tcp_states[arg1];
	this->astate = tcp_states[arg2];
}

tcp-flow-state /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(FMT, this->bstate, this->astate, this->s);
}

tcp-flow-state /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(FMT, this->bstate, this->astate, this->s);
}
