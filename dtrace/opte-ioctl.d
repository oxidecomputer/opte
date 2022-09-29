/*
 * Track the OPTE command ioctls as they come in.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-ioctl.d
 */
xde_dld_ioc_opte_cmd:entry {
	this->opte_cmd_ioctl = (opte_cmd_ioctl_t *)arg0;
	print(*this->opte_cmd_ioctl);
	printf("\n");
	self->t = 1;
}

ddi_copyin:entry /self->t/ {
	printf("ddi_copyin(%p, %p, %u, 0x%x) =>", arg0, arg1, arg2, arg3);
}

ddi_copyin:return /self->t/ {
	printf(" %d\n", arg1);
}

xde_dld_ioc_opte_cmd:return {
	self->t = 0;
}
