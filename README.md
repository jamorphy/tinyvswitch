# tinyvswitch

A minimal virtual switch implementation, works on anything with a `net_device`.

## Features
- Unicast/broadcast packet forwarding
- MAC learning
- Packet flooding

## Usage

Clone and build the source, load the kernel module.
```
make
sudo insmod vswitch.ko
```

Create a client/VM. In this case I'm creating a veth pair with a namespace on one end
to mimic a VM (see `scripts/create_vm`).
```
sudo ./scripts/create-vm vm1 00:11:11:11:11:11 192.168.1.1/24
VM network setup complete for vm1
```

The module is exposed to userspace via sysfs. To add and remove an interface:
```
echo "vm1-eth0-end" | sudo tee /sys/kernel/vswitch/add_interface
echo "vm1-eth0-end" | sudo tee /sys/kernel/vswitch/remove_interface
```

A basic test suite can be found in `tests/`.

## Why?
Just for fun

## Features to add
- VLAN tagging
- Port mirroring
- Multicast support (IGMP snooping)
