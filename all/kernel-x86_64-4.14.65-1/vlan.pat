diff --git a/net/8021q/vlan_netlink.c b/net/8021q/vlan_netlink.c
index 5e831de3103e..9472de846d5c 100644
--- a/net/8021q/vlan_netlink.c
+++ b/net/8021q/vlan_netlink.c
@@ -143,6 +143,7 @@ static int vlan_newlink(struct net *src_net, struct net_device *dev,
 	vlan->vlan_proto = proto;
 	vlan->vlan_id	 = nla_get_u16(data[IFLA_VLAN_ID]);
 	vlan->real_dev	 = real_dev;
+	dev->priv_flags |= (real_dev->priv_flags & IFF_XMIT_DST_RELEASE);
 	vlan->flags	 = VLAN_FLAG_REORDER_HDR;
 
 	err = vlan_check_real_dev(real_dev, vlan->vlan_proto, vlan->vlan_id);
