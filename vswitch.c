#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct vs_port {
    uint32_t id;
    struct net_device *dev;
    struct list_head list; // prev and next ptrs, used for adding to ports list
};

struct vs {
    struct list_head ports; // switch-wide ports list
    uint8_t num_ports;
    spinlock_t lock;
} vs;

static struct vs *vswitch;
static struct kobject *vs_kobj;

static rx_handler_result_t vs_Rx(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb; // socket buffer
    struct ethhdr *eth;
    struct iphdr *ip;
    unsigned char *mac_src, *mac_dst;

    pr_info("vswitch: Received packet on %s, length: %d\n", skb->dev->name, skb->len);

    // Ensure the packet is large enough to contain an Ethernet header
    if (skb->len < ETH_HLEN) {
        pr_err("vswitch: Packet too short to contain Ethernet header\n");
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }

    // Get the Ethernet header
    eth = eth_hdr(skb);
    if (!eth) {
        pr_err("vswitch: Failed to parse Ethernet header\n");
        return RX_HANDLER_CONSUMED;
    }

    // Extract MAC addresses
    mac_src = eth->h_source;
    mac_dst = eth->h_dest;

    // Print MAC addresses
    pr_info("vswitch: Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
    pr_info("vswitch: Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);

    if (eth->h_proto == htons(ETH_P_IP)) {
        ip = ip_hdr(skb);
        if (ip->protocol == IPPROTO_ICMP) {
            pr_info("vswitch: ICMP packet detected\n");
        }
    }


    // For now, just drop the packet
    kfree_skb(skb);
    return RX_HANDLER_CONSUMED;
}

static int vs_add_port(struct net_device * dev) {
    struct vs_port *port;
    int err;
    unsigned long flags;

    pr_info("vswitch: Adding port for device %s\n", dev->name);

    port = kmalloc(sizeof(*port), GFP_KERNEL);
    if (!port) {
        pr_err("vswitch: Failed to allocate memory for port\n");
        return -ENOMEM;
    }

    port->dev = dev;
    port->id = vswitch->num_ports + 1;

    pr_info("vswitch: Registering rx handler for %s\n", dev->name);
    err = netdev_rx_handler_register(dev, vs_Rx, NULL);
    if (err) {
        pr_err("vswitch: Error registering rx handler for %s\n", dev->name);
        kfree(port);
        return err;
    }

    pr_info("vswitch: Adding port to list\n");
    spin_lock_irqsave(&vswitch->lock, flags);
    port->id = vswitch->num_ports + 1;
    list_add_tail(&port->list, &vswitch->ports);
    vswitch->num_ports++;
    spin_unlock_irqrestore(&vswitch->lock, flags);

    pr_info("vswitch: Added port for device %s\n", dev->name);
    return 0;
}

static ssize_t vs_add_interface(struct device *dev,
                                struct device_attribute *attr,
                                const char *buf, size_t count)
{
    char ifname[IFNAMSIZ];
    struct net_device *netdev;
    int err;

    if (sscanf(buf, "%15s", ifname) != 1) {
        pr_err("vswitch: Invalid interface name\n");
        return -EINVAL;
    }

    pr_info("vswitch: Looking for interface: %s\n", ifname);

    netdev = dev_get_by_name(&init_net, ifname);
    if (!netdev) {
        pr_err("vswitch: Interface %s not found\n", ifname);
        return -ENODEV;
    }

    pr_info("vswitch: Found interface %s, adding port\n", ifname);
    err = vs_add_port(netdev);
    dev_put(netdev);

    if (err) {
        pr_err("vswitch: Failed to add port for %s, error %d\n", ifname, err);
        return err;
    }

    return count;
}

// sysfs attributes
// exposes `add_interface` file, calls `vs_add_interface` when writing to file
static DEVICE_ATTR(add_interface, S_IWUSR, NULL, vs_add_interface);

static struct attribute *vs_attrs[] = {
    &dev_attr_add_interface.attr,
    NULL
};

static struct attribute_group vs_attr_group = {
    .attrs = vs_attrs,
};

static int __init vs_init(void) {
    int result;
    printk(KERN_INFO "Creating vswitch.\n");

    vswitch = kmalloc(sizeof(struct vs), GFP_KERNEL);
    if (!vswitch)
        return -ENOMEM;

    INIT_LIST_HEAD(&vswitch->ports);
    vswitch->num_ports = 0;
    spin_lock_init(&vswitch->lock);

    vs_kobj = kobject_create_and_add("vswitch", kernel_kobj);
    if (!vs_kobj) {
        kfree(vswitch);
        return -ENOMEM;
    }

    result = sysfs_create_group(vs_kobj, &vs_attr_group);
    if (result) {
        kobject_put(vs_kobj);
        kfree(vswitch);
        return -ENOMEM;
    }

    pr_info("vswitch: Loaded\n");
    return 0;
}

static void __exit vs_exit(void) {
    struct vs_port *port, *tmp;
    unsigned long flags;
    printk(KERN_INFO "Destroying vswitch.\n");

    sysfs_remove_group(vs_kobj, &vs_attr_group);

    kobject_put(vs_kobj);

    spin_lock_irqsave(&vswitch->lock, flags);
    list_for_each_entry_safe(port, tmp, &vswitch->ports, list) {
        if (port->dev) {
            netdev_rx_handler_unregister(port->dev);
        }
        list_del(&port->list);
        kfree(port);
    }
    spin_unlock_irqrestore(&vswitch->lock, flags);
    
    kfree(vswitch);
    pr_info("vswitch: Unloaded\n");
}

module_init(vs_init);
module_exit(vs_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("tinyvswitch");
MODULE_VERSION("0.1");
