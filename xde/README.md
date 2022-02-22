XDE
===

This is an OPTE driver that is also a MAC provider. This driver was developed as
a parallel crate to opte-drv but the idea is that this work will merge back into
opte-drv. The name is just something I chose to not conflict with the existing
opte driver.

## Requirements

- You'll need
[this branch](https://github.com/oxidecomputer/illumos-gate/tree/xde) 
of illumos. **This is not just for the kernel, but also for `dladm` and the
libraries `dladm` links to.**

- The driver currently assumes there are two underlay network devices it can use
  for off-node I/O. This is easily achieved in a VM with viona devices.

## Compilation

The following will create a kernel module `xde`.
```
./compile.sh
./link.sh
```

## Installation

Copy this to `/kernel/drv/amd64/` on the platform you're testing on. Then
copy `xde.conf` to `/kernel/drv/`. Then add the driver.

```
add_drv xde
```

## Usage

Now we can instantiate an xde device.

**NOTE: there is currently a bug in the driver that makes it so it cannot find
underlay devices unless `dladm` has been run at least once. So before
instantiating an xde device run `dladm`.**

The following creates an xde device in pass-through mode, meaning packets are not
actually processed by opte-core, they just pass through the xde device to one of
the two underlay devices. Remove the `--passthrough` flag to enable opte
processing. The `vioif0` and `vioif1` arguments are the underlay devices this
xde instance will use for off-node I/O. The first mac/IP combo are the overlay
addresses associated with this xde instance. The second mac/IP combo belong to
the underlay gateway. `fd00:99::1` is the boudnary services gateway address.
`99` is the boundary services Geneve VNI. `10` is the VPC VNI. `fd00:1::1` is
the underlay source address for the servier this xde is running on.

```
./opteadm xde-create \
	--passthrough \
	xde0 \
	vioif0 vioif1 \
	A8:40:25:ff:00:01 10.0.0.1 \
	A8:40:25:00:00:01 172.30.0.5 \
	fd00:99::1 99 \
	10 \
	fd00:1::1
```

For operating without pass-through mode, there are not currently enough ioctls
from opte-drv present in xde to do anything besides drop packets. However, I
have verified that when pass-through is not enabled, the data does make it's way
into opte-core where it's determined (correctly due to lack of configuration) 
that all packets shall be dropped and nothing escapes to the underlay devices.

For local testing we can layer a vnic atop this xde instance.

```
dladm create-vnic -t -l xde0 vnic0
```

Along with an IP address to match the above xde configuration.

```
ipadm create-addr -t -T static -a 10.0.0.1/24 vnic0/v4
```

You should now see something like this from `dladm`

```
# dladm
LINK        CLASS     MTU    STATE    BRIDGE     OVER
vioif0      phys      1500   up       --         --
vioif1      phys      1500   up       --         --
xde0        xde       1500   up       --         --
vnic0       vnic      1500   up       --         xde0
```

If there is a host connected to this machine on `vioif0` with the address
`10.0.0.2/24` you should now be able to ping that address.

To tear down this setup
```
ipadm delete-addr vnic0/v4
ipadm delete-if vnic0
dladm delete-vnic -t vnic0
./opteadm xde-delete xde0
```
