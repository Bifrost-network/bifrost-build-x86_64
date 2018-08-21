--- net/core/pktgen.c.orig	Mon Jul  3 11:21:29 2017
+++ net/core/pktgen.c	Tue Jul  4 09:37:13 2017
@@ -115,6 +115,7 @@
  * Fixed src_mac command to set source mac of packet to value specified in
  * command by Adit Ranadive <adit.262@gmail.com>
  *
+ * Receiver support and rate control by Daniel Turull <daniel.turull@gmail.com>
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
@@ -158,6 +159,7 @@
 #include <linux/etherdevice.h>
 #include <linux/kthread.h>
 #include <linux/prefetch.h>
+#include <linux/percpu.h>
 #include <net/net_namespace.h>
 #include <net/checksum.h>
 #include <net/ipv6.h>
@@ -177,6 +179,9 @@
 #include <asm/dma.h>
 #include <asm/div64.h>		/* do_div */
 
+#include <linux/netfilter.h>
+#include <linux/netfilter_ipv4.h>
+
 #define VERSION	"2.75"
 #define IP_NAME_SZ 32
 #define MAX_MPLS_LABELS 16 /* This is the max label stack depth */
@@ -221,8 +226,10 @@
 
 /* Used to help with determining the pkts on receive */
 #define PKTGEN_MAGIC 0xbe9be955
+#define PKTGEN_MAGIC_NET htonl(PKTGEN_MAGIC)
 #define PG_PROC_DIR "pktgen"
 #define PGCTRL	    "pgctrl"
+#define PGRX        "pgrx"
 
 #define MAX_CFLOWS  65536
 
@@ -404,12 +411,15 @@
 #endif
 	char result[512];
 };
+#define ntohll(x) (((s64)(ntohl((int)((x << 32) >> 32))) << 32) |\
+	(unsigned int)ntohl(((int)(x >> 32))))
 
+#define htonll(x) ntohll(x)
+
 struct pktgen_hdr {
 	__be32 pgh_magic;
 	__be32 seq_num;
-	__be32 tv_sec;
-	__be32 tv_usec;
+	__s64 time;
 };
 
 
@@ -440,6 +450,47 @@
 	struct pktgen_net *net;
 };
 
+#define RX_COUNTER	1
+#define RX_BASIC	2
+#define RX_TIME		3
+#define PG_DISPLAY_HUMAN 0
+#define PG_DISPLAY_SCRIPT 1
+
+struct pktgen_stats {
+	u64	sum;
+	u64	square_sum;
+	u64	samples;
+	u64	min;
+	u64	max;
+};
+/*Recevier parameters per cpu*/
+struct pktgen_rx {
+	u64 rx_packets;		/*packets arrived*/
+	u64 rx_bytes;		/*bytes arrived*/
+
+	ktime_t start_time;	/*first time stamp of a packet*/
+	ktime_t last_time;	/*last packet arrival */
+
+	/*inter-arrival variables*/
+	struct pktgen_stats inter_arrival;
+	ktime_t last_time_ktime;
+	u64	latency_last;
+
+	struct pktgen_stats jitter;
+
+	struct pktgen_stats latency;
+	ktime_t latency_last_tx;
+
+	struct net *net;
+};
+
+struct pktgen_rx_global {
+	u8 stats_option;		/* Counter, basic, time*/
+	u8 display_option;		/* Text or no text*/
+	u64 pkts_to_send;		/* Received in the config pkt*/
+	u64 bytes_to_send;		/* Received in the config pkt*/
+};
+
 #define REMOVE 1
 #define FIND   0
 
@@ -459,6 +510,16 @@
 static void pktgen_stop(struct pktgen_thread *t);
 static void pktgen_clear_counters(struct pktgen_dev *pkt_dev);
 
+/*Receiver functions*/
+unsigned int pktgen_rcv_counter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
+unsigned int pktgen_rcv_basic(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
+unsigned int pktgen_rcv_time(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
+static int pktgen_add_rx(const char *ifname);
+static int pktgen_set_statistics(const char *f);
+static int pktgen_set_display(const char *f);
+static int pktgen_clean_rx(void);
+static void pg_reset_rx(void);
+
 /* Module parameters, defaults. */
 static int pg_count_d __read_mostly = 1000;
 static int pg_delay_d __read_mostly;
@@ -467,15 +528,28 @@
 
 static DEFINE_MUTEX(pktgen_thread_lock);
 
+DEFINE_PER_CPU(struct pktgen_rx, pktgen_rx_data);
+static struct pktgen_rx_global *pg_rx_global;
+static int pg_initialized;
+static int is_pktgen_sending;
+
 static struct notifier_block pktgen_notifier_block = {
 	.notifier_call = pktgen_device_event,
 };
 
+/*Reception functions test*/
+static struct nf_hook_ops nfho __read_mostly = {
+	.hook = pktgen_rcv_basic,
+	.hooknum = NF_INET_PRE_ROUTING,
+	.pf = PF_INET,
+	.priority = 1,
+	//.owner = THIS_MODULE,
+};
+
 /*
  * /proc handling functions
  *
  */
-
 static int pgctrl_show(struct seq_file *seq, void *v)
 {
 	seq_puts(seq, version);
@@ -1950,6 +2024,260 @@
 	.release = single_release,
 };
 
+
+#define DISPLAY_RX(opt, seq, fmt, fmt1, args...)	\
+	do {						\
+		if (opt == PG_DISPLAY_HUMAN)		\
+			seq_printf(seq, fmt1 , ## args);\
+		else					\
+			seq_printf(seq, fmt, ## args);	\
+	} while (0)
+
+static void show_stats(int option, struct seq_file *seq, char *name,
+		struct pktgen_stats *stats)
+{
+	u64 average_ns = 0, var_ns2 = 0;
+	if (stats->samples < 1)
+		return;
+	average_ns = div64_u64(stats->sum, stats->samples);
+	var_ns2 = div64_u64(stats->square_sum, stats->samples) - (average_ns*average_ns);
+	if (option == PG_DISPLAY_HUMAN)
+		seq_printf(seq, "\t%s\n", name);
+
+	DISPLAY_RX(option, seq, "%llu %llu ",
+		"\t\tAverage: %llu ns Variance %llu ns2\n",
+		average_ns, var_ns2);
+	DISPLAY_RX(option, seq, "%llu %llu ",
+		"\t\tMax: %llu ns Min:: %llu ns\n",
+		stats->max, stats->min);
+	DISPLAY_RX(option, seq, "%llu ",
+		"\t\tSamples: %llu\n",
+		stats->samples);
+}
+
+static void show_bw(int option, struct seq_file *seq, ktime_t start,
+		ktime_t stop, u64 packets, u64 bytes)
+{
+	u64 work_time_us = 0;
+	__u64 bps, mbps, pps;
+	work_time_us = ktime_to_us(ktime_sub(stop, start));
+
+	if (!work_time_us) {
+		if (option == PG_DISPLAY_SCRIPT)
+			seq_puts(seq, "0 0 0 0 ");
+		return;
+	}
+
+	bps = div64_u64(bytes*8*USEC_PER_SEC, work_time_us);
+	mbps = bps;
+	do_div(mbps, 1000000);
+	pps = div64_u64(packets * USEC_PER_SEC, work_time_us);
+
+	DISPLAY_RX(option, seq, "%llu ", "\tWork time %llu us\n",
+		work_time_us);
+	DISPLAY_RX(option, seq, "%llu %llu %llu ",
+		"\tRate:  %llupps %lluMb/sec (%llubps)\n",
+		(unsigned long long)pps,
+		(unsigned long long)mbps,
+		(unsigned long long)bps);
+}
+
+/*
+ * Function that show Receiver statistics
+ */
+static int pgrx_show(struct seq_file *seq, void *v)
+{
+	struct pktgen_rx *data_cpu;
+	int cpu;
+	int option = PG_DISPLAY_HUMAN;
+	u64 total_packets = 0, total_bytes = 0;
+	u64 packets = 0, bytes = 0;
+	ktime_t start_global, stop_global, tmp;
+	start_global = 0;
+	stop_global = 0;
+
+	if (!pg_initialized) {
+		seq_puts(seq, "Not enabled.\n");
+		return 0;
+	}
+	option = pg_rx_global->display_option;
+	if (option == PG_DISPLAY_HUMAN)
+		seq_puts(seq, "\t\tRECEPTION STATISTICS\n");
+	if (option == PG_DISPLAY_HUMAN)
+		seq_puts(seq, "\tPER-CPU Stats\n");
+
+	for_each_online_cpu(cpu) {
+		data_cpu = &per_cpu(pktgen_rx_data, cpu);
+		DISPLAY_RX(option, seq, "%d ", "CPU %d:", cpu);
+		packets = data_cpu->rx_packets;
+		bytes = data_cpu->rx_bytes;
+
+		total_packets = total_packets + packets;
+		total_bytes += bytes;
+		DISPLAY_RX(option, seq, "%llu %llu ",
+			"\tRx packets: %llu\t Rx bytes: %llu\n",
+			packets, bytes);
+
+		tmp = data_cpu->start_time;
+		if (start_global == 0 && tmp != 0)
+			start_global = tmp;
+		else if (tmp < start_global && tmp != 0)
+			start_global = tmp;
+
+		tmp = data_cpu->last_time;
+		if (ktime_to_ns(tmp) > ktime_to_ns(stop_global))
+			stop_global = tmp;
+
+		show_bw(option, seq, data_cpu->start_time, data_cpu->last_time,
+			packets, bytes);
+
+		show_stats(option, seq, "Inter-arrival",
+			&data_cpu->inter_arrival);
+		show_stats(option, seq, "Jitter",
+			&data_cpu->jitter);
+		show_stats(option, seq, "Latency",
+			&data_cpu->latency);
+		if (option == PG_DISPLAY_SCRIPT)
+			seq_puts(seq, "\n");
+	}
+
+	DISPLAY_RX(option, seq, "G ", "\n\tGlobal Statistics\n");
+
+	DISPLAY_RX(option, seq, "%llu %llu ",
+		"Packets Rx: %llu\t Bytes Rx: %llu\n",
+		(unsigned long long) total_packets,
+		(unsigned long long) total_bytes);
+	/*Bandwidth*/
+	show_bw(option, seq, start_global, stop_global, total_packets,
+		total_bytes);
+	if (option == PG_DISPLAY_SCRIPT)
+		seq_puts(seq, "\n");
+	return 0;
+}
+/*receiver configuration*/
+static ssize_t pgrx_write(struct file *file, const char __user * user_buffer,
+				size_t count, loff_t *ppos)
+{
+	int i = 0, max, len, ret;
+	char name[40];
+
+	if (count < 1)
+		return -EINVAL;
+
+	max = count - i;
+	len = count_trail_chars(&user_buffer[i], max);
+	if (len < 0)
+		return len;
+
+	i += len;
+
+	/* Read variable name */
+
+	len = strn_len(&user_buffer[i], sizeof(name) - 1);
+	if (len < 0)
+		return len;
+
+	memset(name, 0, sizeof(name));
+	if (copy_from_user(name, &user_buffer[i], len))
+		return -EFAULT;
+	i += len;
+
+	max = count - i;
+	len = count_trail_chars(&user_buffer[i], max);
+	if (len < 0)
+		return len;
+
+	i += len;
+
+	if (debug)
+		printk(KERN_DEBUG "pktgen: t=%s, count=%lu\n",
+		       name, (unsigned long)count);
+
+	if (!strcmp(name, "rx")) {
+		char f[32];
+		memset(f, 0, 32);
+		len = strn_len(&user_buffer[i], sizeof(f) - 1);
+		if (len < 0) {
+			ret = len;
+			goto out;
+		}
+		if (copy_from_user(f, &user_buffer[i], len))
+			return -EFAULT;
+		i += len;
+
+		if (debug)
+			printk(KERN_INFO "pktgen: Adding rx %s\n", f);
+		pktgen_add_rx(f);
+		ret = count;
+		goto out;
+	} else if (!strcmp(name, "rx_reset")) {
+		ret = count;
+		pg_reset_rx();
+		if (debug)
+			printk(KERN_INFO "pktgen: Reseting reception\n");
+		goto out;
+	} else if (!strcmp(name, "statistics")) {
+		char f[32];
+		memset(f, 0, 32);
+		len = strn_len(&user_buffer[i], sizeof(f) - 1);
+		if (len < 0) {
+			ret = len;
+			goto out;
+		}
+		if (copy_from_user(f, &user_buffer[i], len))
+			return -EFAULT;
+		i += len;
+		if (debug)
+			printk(KERN_INFO "Setting statistics to %s\n", f);
+		pktgen_set_statistics(f);
+		ret = count;
+		goto out;
+	} else if (!strcmp(name, "display")) {
+		char f[32];
+		memset(f, 0, 32);
+		len = strn_len(&user_buffer[i], sizeof(f) - 1);
+		if (len < 0) {
+			ret = len;
+			goto out;
+		}
+		if (copy_from_user(f, &user_buffer[i], len))
+			return -EFAULT;
+		i += len;
+
+		if (debug)
+			printk(KERN_INFO "Setting display to %s\n", f);
+		pktgen_set_display(f);
+		ret = count;
+		goto out;
+	} else if (!strcmp(name, "rx_disable")) {
+		ret = count;
+		pktgen_clean_rx();
+		if (debug)
+			printk(KERN_INFO "pktgen: Cleaning reception\n");
+		goto out;
+	} else
+		printk(KERN_WARNING "pktgen: Unknown command: %s\n", name);
+
+	ret = count;
+
+out:
+	return ret;
+}
+
+static int pgrx_open(struct inode *inode, struct file *file)
+{
+	return single_open(file, pgrx_show, PDE_DATA(inode));
+}
+
+static const struct file_operations pktgen_rx_fops = {
+	.owner   = THIS_MODULE,
+	.open    = pgrx_open,
+	.read    = seq_read,
+	.llseek  = seq_lseek,
+	.write   = pgrx_write,
+	.release = single_release,
+};
+
 /* Think find or remove for NN */
 static struct pktgen_dev *__pktgen_NN_threads(const struct pktgen_net *pn,
 					      const char *ifname, int remove)
@@ -2711,7 +3039,6 @@
 static void pktgen_finalize_skb(struct pktgen_dev *pkt_dev, struct sk_buff *skb,
 				int datalen)
 {
-	struct timeval timestamp;
 	struct pktgen_hdr *pgh;
 
 	pgh = (struct pktgen_hdr *)skb_put(skb, sizeof(*pgh));
@@ -2770,12 +3097,9 @@
 	pgh->seq_num = htonl(pkt_dev->seq_num);
 
 	if (pkt_dev->flags & F_NO_TIMESTAMP) {
-		pgh->tv_sec = 0;
-		pgh->tv_usec = 0;
+		pgh->time = 0;
 	} else {
-		do_gettimeofday(&timestamp);
-		pgh->tv_sec = htonl(timestamp.tv_sec);
-		pgh->tv_usec = htonl(timestamp.tv_usec);
+		pgh->time = htonll(ktime_to_ns(ktime_get()));
 	}
 }
 
@@ -3121,6 +3445,7 @@
 
 	func_enter();
 
+	is_pktgen_sending = 1;
 	mutex_lock(&pktgen_thread_lock);
 
 	list_for_each_entry(t, &pn->pktgen_threads, th_list)
@@ -3174,6 +3499,7 @@
 		list_for_each_entry(t, &pn->pktgen_threads, th_list)
 			t->control |= (T_STOP);
 
+	is_pktgen_sending = 0;
 	mutex_unlock(&pktgen_thread_lock);
 	return sig;
 }
@@ -3184,6 +3510,7 @@
 
 	func_enter();
 
+	is_pktgen_sending = 1;
 	mutex_lock(&pktgen_thread_lock);
 
 	list_for_each_entry(t, &pn->pktgen_threads, th_list)
@@ -3260,6 +3587,7 @@
 	kfree_skb(pkt_dev->skb);
 	pkt_dev->skb = NULL;
 	pkt_dev->stopped_at = ktime_get();
+	pkt_dev->running = 0;
 
 	show_results(pkt_dev, nr_frags);
 
@@ -3838,24 +4166,293 @@
 		pkt_dev->odev = NULL;
 	}
 
-	/* Remove proc before if_list entry, because add_device uses
-	 * list to determine if interface already exist, avoid race
-	 * with proc_create_data() */
-	proc_remove(pkt_dev->entry);
-
 	/* And update the thread if_list */
+
 	_rem_dev_from_if_list(t, pkt_dev);
 
+	if (pkt_dev->entry)
+		proc_remove(pkt_dev->entry);
+
 #ifdef CONFIG_XFRM
 	free_SAs(pkt_dev);
 #endif
 	vfree(pkt_dev->flows);
 	if (pkt_dev->page)
 		put_page(pkt_dev->page);
-	kfree_rcu(pkt_dev, rcu);
+	kfree(pkt_dev);
 	return 0;
 }
+void pg_init_stats(struct pktgen_stats *stats)
+{
+	stats->sum = 0;
+	stats->square_sum = 0;
+	stats->min = ULLONG_MAX;
+	stats->max = 0;
+	stats->samples = 0;
+}
+void pg_reset_rx(void)
+{
+	int cpu;
+	for_each_online_cpu(cpu) {
+		per_cpu(pktgen_rx_data, cpu).rx_packets = 0;
+		per_cpu(pktgen_rx_data, cpu).rx_bytes = 0;
+		per_cpu(pktgen_rx_data, cpu).last_time = 0;
+		per_cpu(pktgen_rx_data, cpu).start_time = 0;
+		per_cpu(pktgen_rx_data, cpu).latency_last = 0;
+		per_cpu(pktgen_rx_data, cpu).last_time_ktime = 0;
+		per_cpu(pktgen_rx_data, cpu).latency_last_tx = 0;
+		pg_init_stats(&per_cpu(pktgen_rx_data, cpu).inter_arrival);
+		pg_init_stats(&per_cpu(pktgen_rx_data, cpu).jitter);
+		pg_init_stats(&per_cpu(pktgen_rx_data, cpu).latency);
+	}
+	if (pg_initialized) {
+		pg_rx_global->pkts_to_send = 0;
+		pg_rx_global->bytes_to_send = 0;
+	}
+}
 
+static int pktgen_add_rx(const char *ifname)
+{
+	int err = 0;
+	struct net_device *idev = NULL;
+
+	pg_reset_rx();
+
+	idev = dev_get_by_name(&init_net, ifname);
+
+	if (!idev)
+		printk(KERN_INFO
+			"pktgen: device not present %s. Using all\n", ifname);
+
+	if (!pg_initialized) {
+		pg_rx_global = kmalloc(sizeof(struct pktgen_rx_global),
+			GFP_KERNEL);
+		pg_rx_global->stats_option = RX_BASIC;
+		pg_rx_global->display_option = PG_DISPLAY_HUMAN;
+
+		nfho.hook = pktgen_rcv_basic;
+		nf_register_net_hook(&init_net, &nfho);
+		//dev_add_pack(&pktgen_packet_type);
+		err = 0;
+		//net_disable_timestamp();
+		pg_initialized = 1;
+	} else {
+		//dev_remove_pack(&pktgen_packet_type);
+		//pktgen_packet_type.dev = idev;
+		//dev_add_pack(&pktgen_packet_type);
+		err = 0;
+	}
+	if (idev)
+		dev_put(idev);
+	return err;
+}
+
+/*Function for select the type of statisitcs*/
+static int pktgen_set_statistics(const char *f)
+{
+	int ret = 0;
+	if (pg_rx_global == NULL)
+		return -ENOMEM;
+
+	//net_disable_timestamp();
+	nf_unregister_net_hook(&init_net, &nfho);
+
+	if (!strcmp(f, "counter")) {
+		pg_rx_global->stats_option = RX_COUNTER;
+		nfho.hook = pktgen_rcv_counter;
+		ret = 0;
+	} else if (!strcmp(f, "basic")) {
+		pg_rx_global->stats_option = RX_BASIC;
+		nfho.hook = pktgen_rcv_basic;
+		ret = 0;
+	} else if (!strcmp(f, "time")) {
+		pg_rx_global->stats_option = RX_TIME;
+		nfho.hook = pktgen_rcv_time;
+		ret = 0;
+	} else
+		ret = -EINVAL;
+
+	nf_register_net_hook(&init_net, &nfho);
+	return ret;
+}
+
+static int pktgen_set_display(const char *f)
+{
+	if (pg_rx_global == NULL)
+		return -ENOMEM;
+	if (!strcmp(f, "human")) {
+		pg_rx_global->display_option = PG_DISPLAY_HUMAN;
+		return 0;
+	} else if (!strcmp(f, "script")) {
+		pg_rx_global->display_option = PG_DISPLAY_SCRIPT;
+		return 0;
+	} else
+		return -EINVAL;
+}
+
+/*
+ * Function for clean the statitics and disable the reception of packets
+ */
+static int pktgen_clean_rx(void)
+{
+	if (pg_initialized) {
+		nf_unregister_net_hook(&init_net, &nfho);
+		kfree(pg_rx_global);
+		pg_initialized = 0;
+	}
+	return 0;
+}
+/*
+ * Function that gets the necessary data for througput calculation
+ */
+static inline int throughput_data(ktime_t now, struct pktgen_rx *data_cpu)
+{
+	if (unlikely(data_cpu->rx_packets == 0))
+		data_cpu->start_time = now;
+	data_cpu->last_time = now;
+
+	return 0;
+}
+
+void process_stats(u64 value, struct pktgen_stats *stats)
+{
+	stats->square_sum += value*value;
+	stats->sum += value;
+
+	stats->samples++;
+
+	if (value > stats->max)
+		stats->max = value;
+	if (value < stats->min)
+		stats->min = value;
+}
+/*
+ * Function to collect inter_arrival data
+*/
+static int inter_arrival_ktime(ktime_t now, struct pktgen_rx *data_cpu)
+{
+	ktime_t last_time;
+	u64 inter_arrival = 0;
+
+	last_time = data_cpu->last_time_ktime;
+	if (last_time == 0) {
+		data_cpu->last_time_ktime = now;
+		return 0;
+	}
+
+	inter_arrival = ktime_to_ns(ktime_sub(now, last_time));
+	process_stats(inter_arrival,
+			&data_cpu->inter_arrival);
+	data_cpu->last_time_ktime = now;
+
+	return 0;
+}
+
+static int latency_calc(struct pktgen_hdr *pgh, ktime_t now,
+		struct pktgen_rx *data_cpu)
+{
+	u64 latency = 0;
+	u64 jitter = 0;
+	ktime_t ktime_tx;
+	if (!is_pktgen_sending)
+		return 0;
+	ktime_tx = ntohll(pgh->time);
+
+	if (ktime_tx == data_cpu->latency_last_tx)
+		return 0;
+	latency = ktime_to_ns(ktime_sub(now, ktime_tx));
+	process_stats(latency, &data_cpu->latency);
+
+	/*Jitter calculation*/
+	/*  J = |(R1 - S1) - (R0 - S0)| */
+	if (latency > data_cpu->latency_last)
+		jitter = latency - data_cpu->latency_last;
+	else
+		jitter = data_cpu->latency_last - latency;
+
+	process_stats(jitter, &data_cpu->jitter);
+
+	/*Memory for next iteration*/
+	data_cpu->latency_last_tx = ktime_tx;
+	data_cpu->latency_last = latency;;
+	return 0;
+}
+
+/*Reception function*/
+unsigned int pktgen_rcv_counter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
+{
+	struct pktgen_hdr *pgh;
+	struct pktgen_rx *data_cpu;
+	int ret = NF_DROP;
+
+	pgh = (struct pktgen_hdr *)(((char *)(skb_transport_header(skb))) + 8);
+
+	if (unlikely(pgh->pgh_magic != PKTGEN_MAGIC_NET)){
+		ret = NF_ACCEPT;
+		goto end;
+	}
+	data_cpu = this_cpu_ptr(&pktgen_rx_data);
+	/* Update counter of packets*/
+	data_cpu->rx_packets++;
+	data_cpu->rx_bytes += skb->len + ETH_HLEN;
+
+end:
+	return ret;
+}
+
+unsigned int pktgen_rcv_time(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
+{
+	struct pktgen_hdr *pgh;
+	struct pktgen_rx *data_cpu;
+	ktime_t now = ktime_get();
+	int ret = NF_DROP;
+
+	pgh = (struct pktgen_hdr *)(((char *)(skb_transport_header(skb))) + 8);
+
+	if (unlikely(pgh->pgh_magic != PKTGEN_MAGIC_NET)){
+		ret = NF_ACCEPT;
+		goto end;
+	}
+
+	data_cpu = this_cpu_ptr(&pktgen_rx_data);
+
+	inter_arrival_ktime(now, data_cpu);
+
+	latency_calc(pgh, now, data_cpu);
+
+	throughput_data(now, data_cpu);
+	/* Update counter of packets*/
+	data_cpu->rx_packets++;
+	data_cpu->rx_bytes += skb->len + ETH_HLEN;
+end:
+	return ret;
+}
+
+unsigned int pktgen_rcv_basic(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
+{
+	struct pktgen_hdr *pgh;
+	struct pktgen_rx *data_cpu;
+	int ret = NF_DROP;
+
+	pgh = (struct pktgen_hdr *)(((char *)(skb_transport_header(skb))) + 8);
+
+	if (unlikely(pgh->pgh_magic != PKTGEN_MAGIC_NET)){
+		ret = NF_ACCEPT;
+		goto end;
+	}
+
+	data_cpu = this_cpu_ptr(&pktgen_rx_data);
+
+	throughput_data(ktime_get(), data_cpu);
+
+	/*update counter of packets*/
+	data_cpu->rx_packets++;
+	data_cpu->rx_bytes += skb->len + ETH_HLEN;
+end:
+	return ret;
+}
+
+
 static int __net_init pg_net_init(struct net *net)
 {
 	struct pktgen_net *pn = net_generic(net, pg_net_id);
@@ -3877,6 +4474,14 @@
 		goto remove;
 	}
 
+	/*Create proc rx*/
+	pe = proc_create(PGRX, 0600, pn->proc_dir, &pktgen_rx_fops);
+	if (pe == NULL) {
+		pr_err("pktgen: cannot create %s procfs entry.\n", PGRX);
+		ret = -EINVAL;
+		goto remove_rx;
+	}
+
 	for_each_online_cpu(cpu) {
 		int err;
 
@@ -3894,6 +4499,8 @@
 
 	return 0;
 
+remove_rx:
+	remove_proc_entry(PGRX, pn->proc_dir);
 remove_entry:
 	remove_proc_entry(PGCTRL, pn->proc_dir);
 remove:
@@ -3924,6 +4531,7 @@
 	}
 
 	remove_proc_entry(PGCTRL, pn->proc_dir);
+	remove_proc_entry(PGRX, pn->proc_dir);
 	remove_proc_entry(PG_PROC_DIR, pn->net->proc_net);
 }
 
@@ -3951,6 +4559,8 @@
 
 static void __exit pg_cleanup(void)
 {
+	pktgen_clean_rx();
+
 	unregister_netdevice_notifier(&pktgen_notifier_block);
 	unregister_pernet_subsys(&pg_net_ops);
 	/* Don't need rcu_barrier() due to use of kfree_rcu() */
