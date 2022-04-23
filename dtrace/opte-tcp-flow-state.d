/*
 * Track TCP flows as they change state.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-tcp-flow-state.d
 */
#include "common.h"

#define	FMT	"%-16s %-12s %-12s %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 * It's always going to be TCP but we need this declared so
	 * the FLOW_FMT macros work.
	 */
	protos[6] = "TCP";

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

	printf(FMT, "PORT", "CURR", "NEW", "FLOW");
	num = 0;
}

tcp-flow-state {
	this->port = stringof(arg0);
	this->flow = (flow_id_sdt_arg_t *)arg1;
	this->af = this->flow->af;
	this->curr = tcp_states[arg2];
	this->new = tcp_states[arg3];

	if (num >= 10) {
		printf(FMT, "PORT", "CURR", "NEW", "FLOW");
		num = 0;
	}

	num++;
}

tcp-flow-state /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(FMT, this->port, this->curr, this->new, this->s);
}

tcp-flow-state /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(FMT, this->port, this->curr, this->new, this->s);
}
