mac_client_set_flow_cb:entry {
	printf("entry: mip %p mrh %p mp  %p",
		arg0, arg1, arg2);
}

mac_client_set_flow_cb:return {
	printf("donezo off %p val %p", arg0, arg1);
}

flow_transport_lport_match:entry {
	printf("entry: mip %p mrh %p mp %p", arg0, arg1, arg2);
}

flow_transport_lport_match:return {
	printf("donezo off %p val %p", arg0, arg1);
}
