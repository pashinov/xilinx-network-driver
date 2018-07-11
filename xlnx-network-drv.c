#include <linux/init.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/moduleparam.h>

#include <linux/of.h>
#include <linux/irq.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/dma-mapping.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/interrupt.h>

#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>

#include <linux/in6.h>
#include <asm/checksum.h>

#include <linux/fs.h>

#define DRIVER_NAME "xlnx-network-drv"

#define REG_DMA_CR	0x00C0		// control register of DMA (zero bit - run DMA MM2P)
#define REG_DMA_SR	0x00C4		// status register of DMA (first bit - interrupt intr_rx)
#define REG_DMA_IR	0x00C8		// enable interrupt of DMA (first bit - interrupt intr_rx)
#define REG_DMA_SA	0x00CC		// source address
#define REG_DMA_DA	0x00D0		// destination address
#define REG_DMA_SL	0x00D4		// data lenght of source DMA
#define REG_DMA_DL	0x00D8		// data lenght of destination DMA (read only)
#define REG_MLIP_SR	0x0100		// status register of MLIP (zero bit - intr_tx)
#define	REG_MLIP_IR	0x0104		// enable interrupt of MLIP (zero bit - intr_tx)

#define DMA_LENGTH 2048

struct net_device_priv {
	void __iomem *base;
	struct sk_buff *skb;
	struct kobject *mykobj;
	struct resource resource;
	struct net_device_stats stats;

	char *src_addr;
	char *dst_addr;
	dma_addr_t src_handle;
	dma_addr_t dst_handle;

	int irq_rx;
	int irq_tx;

	spinlock_t lock;

	struct tasklet_struct tasklet_rx;
};

struct netdev_attr {
	struct attribute attr;
	int value;

	struct net_device_priv *priv;
};

static struct netdev_attr sysfs_param = {
	.attr.name = "sysfs_param",
	.attr.mode = 0644,
	.value = 0,
	.priv = NULL,
};

static struct attribute * netdev_attr[] = {
	&sysfs_param.attr,

	NULL
};

void netdev_set_attr_priv(struct net_device_priv *priv)
{
	sysfs_param.priv = priv;
}

static __inline void netdev_write_reg(struct net_device_priv *priv, const unsigned int reg_addr, const unsigned int reg_value) {
	iowrite32(reg_value, (void __iomem *)(priv->base + reg_addr));
}

static __inline unsigned int netdev_read_reg(struct net_device_priv *priv, const unsigned int reg_addr) {
	return ioread32((void __iomem *)(priv->base + reg_addr));
}

static ssize_t sysfs_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct netdev_attr *a = container_of(attr, struct netdev_attr, attr);
	return scnprintf(buf, PAGE_SIZE, "%d\n", a->value);
}

static ssize_t sysfs_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t len)
{
	unsigned long flags;
	struct netdev_attr *a = container_of(attr, struct netdev_attr, attr);

	spin_lock_irqsave(&a->priv->lock, flags);

	sscanf(buf, "%d", &a->value);

	spin_unlock_irqrestore(&a->priv->lock, flags);

	return len;
}

static irqreturn_t netdev_irq_rx_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = (struct net_device *)dev_id;
	struct net_device_priv *priv = netdev_priv(dev);

	netdev_write_reg(priv, REG_DMA_SR, 2);

	tasklet_schedule(&priv->tasklet_rx);

	return IRQ_HANDLED;
}

static irqreturn_t netdev_irq_tx_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = (struct net_device *)dev_id;
	struct net_device_priv *priv = netdev_priv(dev);

	netdev_write_reg(priv, REG_MLIP_SR, 1);

	priv->stats.tx_packets++;
	priv->stats.tx_bytes += priv->skb->len;
	dev_kfree_skb_irq(priv->skb);

	netif_wake_queue(dev);

	return IRQ_HANDLED;
}

static int netdev_start(struct net_device_priv *priv)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	netdev_write_reg(priv, REG_DMA_SA, priv->src_handle);
	netdev_write_reg(priv, REG_DMA_DA, priv->dst_handle);

	netdev_write_reg(priv, REG_MLIP_IR, 1);
	netdev_write_reg(priv, REG_DMA_IR, 2);

	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

static int netdev_open(struct net_device *dev)
{
	struct net_device_priv *priv = netdev_priv(dev);

	if (request_irq(priv->irq_rx, (void *)netdev_irq_rx_handler, IRQF_SHARED, DRIVER_NAME, dev)) {
		return -ENOMEM;
	}
	if (request_irq(priv->irq_tx, (void *)netdev_irq_tx_handler, IRQF_SHARED, DRIVER_NAME, dev)) {
		return -ENOMEM;
	}

	priv->src_addr = dma_zalloc_coherent(NULL, DMA_LENGTH, &priv->src_handle, GFP_KERNEL);
	priv->dst_addr = dma_zalloc_coherent(NULL, DMA_LENGTH, &priv->dst_handle, GFP_KERNEL);

	netdev_start(priv);

	netif_start_queue(dev);

	return 0;
}

static int netdev_release(struct net_device *dev)
{
	struct net_device_priv *priv = netdev_priv(dev);

	free_irq(priv->irq_rx, dev);
	free_irq(priv->irq_tx, dev);

	dma_free_coherent(NULL, DMA_LENGTH, priv->src_addr, priv->src_handle);
	dma_free_coherent(NULL, DMA_LENGTH, priv->dst_addr, priv->dst_handle);

	netif_stop_queue(dev);

	return 0;
}

static void netdev_rx(struct net_device *dev)
{
	char *data;
	int	datalen;
	struct sk_buff *skb;

	struct net_device_priv *priv = netdev_priv(dev);

	data = priv->dst_addr;
	datalen = netdev_read_reg(priv, REG_DMA_DL);

	skb = dev_alloc_skb(datalen + 2);
	if (!skb) {
		priv->stats.rx_dropped++;
		return;
	}

	skb_reserve(skb, 2);
	memcpy(skb_put(skb, datalen), data, datalen);

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = eth_type_trans(skb, dev);
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += datalen;

	netif_rx(skb);
}

static int netdev_tx(struct sk_buff *skb, struct net_device *dev)
{
	int datalen;
	unsigned long flags;
	char *data, shortpkt[ETH_ZLEN];
	struct net_device_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);

	netif_stop_queue(dev);

	data = skb->data;
	datalen = skb->len;
	if (datalen < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		datalen = ETH_ZLEN;
		data = shortpkt;
	}
	dev->mem_start = jiffies;

	priv->skb = skb;

	memcpy(priv->src_addr, data, datalen);

	netdev_write_reg(priv, REG_DMA_SL, datalen);
	netdev_write_reg(priv, REG_DMA_CR, 1);

	spin_unlock_irqrestore(&priv->lock, flags);

	return NETDEV_TX_OK;
}

struct net_device_stats *netdev_stats(struct net_device *dev)
{
	struct net_device_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

static void netdev_rewrite_address(const struct net_device *dev, struct ethhdr *eth)
{
	const struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (in_dev) {
		const struct in_ifaddr *ifa = in_dev->ifa_list;
		if (ifa) {
			memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
			memset(eth->h_dest, 0xfe, dev->addr_len);
		}
	}
	rcu_read_unlock();
}

static int netdev_header(struct sk_buff *skb, struct net_device *dev, unsigned short type, const void *daddr, const void *saddr, unsigned len)
{
	int ret;

	ret = eth_header(skb, dev, type, daddr, saddr, len);
	if (ret >= 0) {
		netdev_rewrite_address(dev, (struct ethhdr *)skb->data);
	}

	return ret;
}

static struct sysfs_ops sysfs_netdev_ops = {
	.show = sysfs_show,
	.store = sysfs_store,
};

static struct kobj_type netdev_type = {
	.sysfs_ops = &sysfs_netdev_ops,
	.default_attrs = netdev_attr,
};

static const struct header_ops netdev_header_ops = {
	.create	= netdev_header,
};

static const struct net_device_ops netdev_ops = {
	.ndo_open            = netdev_open,
	.ndo_stop            = netdev_release,
	.ndo_start_xmit      = netdev_tx,
	.ndo_get_stats       = netdev_stats,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_change_mtu      = eth_change_mtu,
	.ndo_validate_addr   = eth_validate_addr,
};

static void netdev_init(struct net_device *dev)
{
	struct net_device_priv *priv;

	ether_setup(dev);

	dev->netdev_ops = &netdev_ops;
	dev->header_ops = &netdev_header_ops;

	dev->flags |= IFF_POINTOPOINT | IFF_NOARP;
	dev->features |= NETIF_F_HW_CSUM;

	memset(dev->dev_addr, 0xfc, ETH_ALEN);

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct net_device_priv));

	spin_lock_init(&priv->lock);
}

static int netdev_probe(struct platform_device *pdev)
{
	int ret = -ENOMEM;
	struct net_device *netdev;
	struct net_device_priv *priv;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0))
	netdev = alloc_netdev(sizeof(struct net_device_priv), "mod%d", netdev_init);
	if (!netdev) {
		ret = -ENOMEM;
		goto out_alloc_netdev;
	}
#else
	netdev = alloc_netdev(sizeof(struct net_device_priv), "mod%d", NET_NAME_UNKNOWN, netdev_init);
	if (!netdev) {
		ret = -ENOMEM;
		goto out_alloc_netdev;
	}
#endif

	priv = netdev_priv(netdev);

	priv->mykobj = kzalloc(sizeof(*priv->mykobj), GFP_KERNEL);
	if (priv->mykobj) {
		kobject_init(priv->mykobj, &netdev_type);
		if (kobject_add(priv->mykobj, NULL, "%s", "netdev")) {
			 printk(KERN_ALERT "Sysfs creation failed\n");
			 kobject_put(priv->mykobj);
			 priv->mykobj = NULL;
			 goto out_alloc_netdev;
		}
	}

	netdev_set_attr_priv(priv);

	ret = register_netdev(netdev);
	if(ret) {
		goto out_register_netdev;
	}

	ret = of_address_to_resource(pdev->dev.of_node, 0, &priv->resource);
	if (ret) {
		goto out_resource_region;
	}

	if (!request_mem_region(priv->resource.start, resource_size(&priv->resource), DRIVER_NAME)) {
		goto out_resource_region;
	}

	priv->base = of_iomap(pdev->dev.of_node, 0);
	if (!priv->base) {
		goto out_iomap;
	}

	priv->irq_rx = irq_of_parse_and_map(pdev->dev.of_node, 0);
	priv->irq_tx = irq_of_parse_and_map(pdev->dev.of_node, 1);

	tasklet_init(&priv->tasklet_rx, (void *)netdev_rx, (unsigned long)netdev);

	dev_set_drvdata(&pdev->dev, netdev);

	printk(KERN_INFO "%s: interface registered\n", DRIVER_NAME);

	return 0;

out_iomap:
	release_mem_region(priv->resource.start, resource_size(&priv->resource));

out_resource_region:
	unregister_netdev(netdev);

out_register_netdev:
	free_netdev(netdev);

out_alloc_netdev:
	printk(KERN_ALERT "%s: register failed\n", DRIVER_NAME);

	return ret;
}

static int netdev_cleanup(struct platform_device *pdev)
{
	struct net_device *netdev = dev_get_drvdata(&pdev->dev);
	struct net_device_priv *priv = netdev_priv(netdev);

	if (priv->mykobj) {
		kobject_put(priv->mykobj);
		kfree(priv->mykobj);
	}

	iounmap(priv->base);
	release_mem_region(priv->resource.start, resource_size(&priv->resource));

	unregister_netdev(netdev);
	free_netdev(netdev);

	printk(KERN_INFO "%s: interface unregistered\n", DRIVER_NAME);

	return 0;
}

static struct of_device_id netdev_of_match[] = {
	{ .compatible = "xlnx,netdev-drv", },
	{  },
	{  },
};

static struct platform_driver netdev_driver = {
	.driver = {
	.name = DRIVER_NAME,
	.owner = THIS_MODULE,
	.of_match_table = of_match_ptr(netdev_of_match),
	},
	.probe = netdev_probe,
	.remove = netdev_cleanup,
};

static int __init netdev_module_init(void)
{
	return platform_driver_register(&netdev_driver);
}

static void __exit netdev_module_exit(void)
{
	platform_driver_unregister(&netdev_driver);
}

module_init(netdev_module_init);
module_exit(netdev_module_exit);

MODULE_DESCRIPTION("Xilinx linux network driver sample");
MODULE_AUTHOR("Alexey Pashinov <pashinov@outlook.com>");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
