#!/bin/bash

set -e

# XXX hack to make sure underlay devices are visible to xde
dladm

underlay1=$(svcprop -c -p config/underlay1 "${SMF_FMRI}")
underlay2=$(svcprop -c -p config/underlay2 "${SMF_FMRI}")

cat << EOF > /kernel/drv/xde.conf
name="xde" parent="pseudo" instance=0;

underlay1 = "$underlay1";
underlay2 = "$underlay2";
EOF

# install xde if not already installed on the system
if `grep -q "^xde" /etc/name_to_major`; then
    # if the driver is already installed just modify configuration files this
    # may happen if the underlay settings are changed through a property group
    update_drv -n xde
else
    add_drv xde
fi
