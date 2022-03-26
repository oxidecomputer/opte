/*
 * MOVING RIGHT ALONG...
 *
 * inet_ntoa() wants an ipaddr_t pointer, but opte is passing
 * up the actual 32-bit IP value. You can't take the address
 * of a dynamic variable, so make local allocations to
 * reference.
 */
#define FLOW_FMT(svar, fvar)					\
	this->src_ip = (ipaddr_t *)alloca(4);			\
	this->dst_ip = (ipaddr_t *)alloca(4);			\
	*this->src_ip = fvar->src_ip4;				\
	*this->dst_ip = fvar->dst_ip4;				\
	svar = protos[fvar->proto];				\
	svar = strjoin(svar, ",");				\
	svar = strjoin(svar, inet_ntoa(this->src_ip));		\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, lltostr(ntohs(fvar->src_port)));	\
	svar = strjoin(svar, ",");				\
	svar = strjoin(svar, inet_ntoa(this->dst_ip));		\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, lltostr(ntohs(fvar->dst_port)));

#define FLOW_FMT6(svar, fvar)					\
	this->src_ip6 = (in6_addr_t *)alloca(16);		\
	this->dst_ip6 = (in6_addr_t *)alloca(16);		\
	*this->src_ip6 = fvar->src_ip6;				\
	*this->dst_ip6 = fvar->dst_ip6;				\
	svar = protos[fvar->proto];				\
	svar = strjoin(svar, ",");				\
	svar = strjoin(svar, inet_ntoa6(this->src_ip6));	\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, lltostr(ntohs(fvar->src_port)));	\
	svar = strjoin(svar, ",");				\
	svar = strjoin(svar, inet_ntoa6(this->dst_ip6));	\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, lltostr(ntohs(fvar->dst_port)));

#define ETH_FMT(svar, evar)					\
	svar = substr(lltostr(evar[0], 16), 2);			\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, substr(lltostr(evar[1], 16), 2));	\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, substr(lltostr(evar[2], 16), 2));	\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, substr(lltostr(evar[3], 16), 2));	\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, substr(lltostr(evar[4], 16), 2));	\
	svar = strjoin(svar, ":");				\
	svar = strjoin(svar, substr(lltostr(evar[5], 16), 2));
