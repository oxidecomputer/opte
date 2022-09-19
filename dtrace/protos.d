/*
 * Definitions of the IP protocol numbers as an associative array.
 */
BEGIN {
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
	protos[58] = "ICMPv6";
	protos[255] = "XXX";
}
