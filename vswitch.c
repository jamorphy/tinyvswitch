#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct vs_port {
    uint32_t id;
    struct net_device *dev;
    struct list_head list; // prev and next ptrs, used for adding to ports list
};

struct mac_entry {
    unsigned char mac[ETH_ALEN];
    struct vs_port *port;
    struct list_head list;
};

struct vs {
    struct list_head ports; // switch-wide ports list
    struct list_head mac_table;
    uint8_t num_ports;
    spinlock_t lock;
};

static struct vs *vswitch;
static struct kobject *vs_kobj;

void print_mac_table(struct vs *vswitch)
{
    struct mac_entry *entry;
    int count = 0;
    unsigned long flags;

    pr_info("vswitch: Printing MAC table contents:\n");

    spin_lock_irqsave(&vswitch->lock, flags);

    list_for_each_entry(entry, &vswitch->mac_table, list) {
        pr_info("vswitch: Entry %d: MAC %pM, Port ID: %d\n",
                count++,
                entry->mac,
                entry->port ? entry->port->id : -1);

        if (count > 1000) {  // Safety check to prevent infinite loops
            pr_warn("vswitch: More than 1000 entries in MAC table. Stopping print.\n");
            break;
        }
    }

    spin_unlock_irqrestore(&vswitch->lock, flags);

    if (count == 0) {
        pr_info("vswitch: MAC table is empty.\n");
    } else {
        pr_info("vswitch: Total entries in MAC table: %d\n", count);
    }
}

static struct vs_port* vs_port_find(struct vs *vswitch, struct net_device *dev)
{
    struct vs_port *port;

    spin_lock(&vswitch->lock);
    list_for_each_entry(port, &vswitch->ports, list) {
        if (port->dev == dev) {
            spin_unlock(&vswitch->lock);
            return port;
        }
    }
    spin_unlock(&vswitch->lock);

    return NULL;
}

/*
 * vs_port
 *
 * Searches the MAC table to return the port associated with a MAC address
 */
static struct vs_port* vs_mac_lookup(struct vs *vswitch,
                                     const unsigned char *mac_addr)
{
    struct mac_entry *entry;
    struct vs_port *port = NULL;

    pr_info("vswitch: Looking up MAC in vs_mac_lookup\n");

    spin_lock(&vswitch->lock);
    list_for_each_entry(entry, &vswitch->mac_table, list) {
        if (memcmp(entry->mac, mac_addr, ETH_ALEN) == 0) {
            pr_info("vswitch: Found MAC entry\n");
            if (entry->port) {
                port = entry->port;
                pr_info("vswitch: Port found, ID: %d\n", port->id);
            } else {
                pr_warn("vswitch: Found MAC entry but port is NULL\n");
            }
            break;
        }
    }
    spin_unlock(&vswitch->lock);

    pr_info("vswitch: Finished looking up MAC\n");

    return port;
}

/*
 * vs_mac_learn
 *
 * Learns or updates a MAC address entry in the MAC table
 */
static struct vs_port* vs_mac_learn(struct vs *vswitch,
                         const unsigned char *mac_addr,
                         struct net_device *dev)
{
    struct mac_entry *entry;
    struct vs_port *port;
    int found = 0;

    port = vs_port_find(vswitch, dev);
    if (!port) {
        pr_err("vswitch: Cannot learn MAC, no port found for device %s\n", dev->name);
        return NULL;
    }

    pr_info("vswitch: Learning MAC %pM for port ID %d\n", mac_addr, port->id);

    spin_lock(&vswitch->lock);
    // Search for existing entry, update if present
    list_for_each_entry(entry, &vswitch->mac_table, list) {
        if (memcmp(entry->mac, mac_addr, ETH_ALEN) == 0) {
            pr_info("vs_mac_learn: MAC entry already present, updating.");
            entry->port = port;
            found = 1;
            break;
        }
    }

    if (!found) {
        pr_info("Adding new MAC entry\n");
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            memcpy(entry->mac, mac_addr, ETH_ALEN);
            entry->port = port;
            list_add(&entry->list, &vswitch->mac_table);
        } else {
            pr_err("vswitch: Failed to allocated memory for new MAC entry\n");
            spin_unlock(&vswitch->lock);
            return NULL;
        }
    }
    spin_unlock(&vswitch->lock);
    return port;
}

/*
 * vs_Tx
 *
 * The dispatch fn, transmits a socket buffer to a dst port
 */
static int vs_Tx(struct vs_port *out_port, struct sk_buff *skb)
{
    struct sk_buff *nskb;
    int ret;

    nskb = skb_clone(skb, GFP_ATOMIC);
    if (!nskb)
        return -ENOMEM;

    nskb->dev = out_port->dev;
    skb_push(nskb, ETH_HLEN);

    ret = dev_queue_xmit(nskb);
    if (ret != NET_XMIT_SUCCESS) {
        kfree_skb(nskb);
        return ret;
    }

    return 0;
}

/*
 * vs_flood
 *
 * Flood the ports on the switch with the sock bufer
 */
static void vs_flood(struct vs *vswitch, struct sk_buff *skb, struct vs_port *src_port)
{
    struct vs_port *port;
    struct sk_buff *nskb;

    list_for_each_entry(port, &vswitch->ports, list) {
        if (port != src_port) {
            pr_info("Flooding port\n");
            nskb = skb_clone(skb, GFP_ATOMIC);
            if (nskb) {
                if (vs_Tx(port, nskb) != 0) {
                    kfree_skb(nskb);
                }
            }
        }
    }
}

/*
 * vs_Rx
 *
 * CB executed when a packet arrives on an ingress port
 */
static rx_handler_result_t vs_Rx(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb; // socket buffer
    struct ethhdr *eth;
    unsigned char *mac_src, *mac_dst;
    struct vs_port *rx_port, *tx_port;
    
    // Ensure the packet is large enough to contain an Ethernet header
    if (skb->len < ETH_HLEN) {
        pr_err("vswitch: Packet too short to contain Ethernet header\n");
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }

    eth = eth_hdr(skb);
    if (!eth) {
        pr_err("vswitch: Failed to parse Ethernet header\n");
        return RX_HANDLER_CONSUMED;
    }

    mac_src = eth->h_source;
    mac_dst = eth->h_dest;

    rx_port = vs_mac_lookup(vswitch, mac_src);
    if (rx_port == NULL) {
        pr_info("vswitch: rx_port null, learning new MAC\n");
        rx_port = vs_mac_learn(vswitch, mac_src, skb->dev); // learn the SRC MAC
        if (rx_port == NULL) {
            pr_err("vswitch: Failed to learn new MAC\n");
            kfree_skb(skb);
            return RX_HANDLER_CONSUMED;
        }
    } else {
        pr_info("vswitch: MAC already known, port ID: %d\n", rx_port->id);
    }

    tx_port = vs_mac_lookup(vswitch, mac_dst);
    if (tx_port == NULL || is_broadcast_ether_addr(mac_dst) || is_multicast_ether_addr(mac_dst)) {
        pr_info("vswitch: tx_port is NULL, flooding\n");
        vs_flood(vswitch, skb, rx_port);
    } else {
        pr_info("vswitch: tx_port known, we can forward the packet\n");
        vs_Tx(tx_port, skb);
    }

    print_mac_table(vswitch);
    // TODO: flood the switch if tx_port is not found, else forward to dst
    
    pr_info("vswitch: Rx on %s, length: %d\n", skb->dev->name, skb->len);
    pr_info("vswitch: Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
    pr_info("vswitch: Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);

    // Drop the packet for now
    kfree_skb(skb);
    return RX_HANDLER_CONSUMED;
}

/*
 * vs_add_port
 * 
 * Adds a port to the switch-wide ports list
 */
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
    vswitch->num_ports++;
    port->id = vswitch->num_ports;
    list_add_tail(&port->list, &vswitch->ports);
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
    INIT_LIST_HEAD(&vswitch->mac_table);
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
