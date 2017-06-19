From 84ac7260236a49c79eede91617700174c2c19b0c Mon Sep 17 00:00:00 2001
From: Philip Pettersson <philip.pettersson@gmail.com>
Date: Wed, 30 Nov 2016 14:55:36 -0800
Subject: packet: fix race condition in packet_set_ring

When packet_set_ring creates a ring buffer it will initialize a
struct timer_list if the packet version is TPACKET_V3. This value
can then be raced by a different thread calling setsockopt to
set the version to TPACKET_V1 before packet_set_ring has finished.

This leads to a use-after-free on a function pointer in the
struct timer_list when the socket is closed as the previously
initialized timer will not be deleted.

The bug is fixed by taking lock_sock(sk) in packet_setsockopt when
changing the packet version while also taking the lock at the start
of packet_set_ring.

Fixes: f6fb8f100b80 ("af-packet: TPACKET_V3 flexible buffer implementation.")
Signed-off-by: Philip Pettersson <philip.pettersson@gmail.com>
Signed-off-by: Eric Dumazet <edumazet@google.com>
Signed-off-by: David S. Miller <davem@davemloft.net>
---
 net/packet/af_packet.c | 18 ++++++++++++------
 1 file changed, 12 insertions(+), 6 deletions(-)

diff --git a/net/packet/af_packet.c b/net/packet/af_packet.c
index d2238b2..dd23323 100644
--- a/net/packet/af_packet.c
+++ b/net/packet/af_packet.c
@@ -3648,19 +3648,25 @@ packet_setsockopt(struct socket *sock, int level, int optname, char __user *optv
 
 		if (optlen != sizeof(val))
 			return -EINVAL;
-		if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
-			return -EBUSY;
 		if (copy_from_user(&val, optval, sizeof(val)))
 			return -EFAULT;
 		switch (val) {
 		case TPACKET_V1:
 		case TPACKET_V2:
 		case TPACKET_V3:
-			po->tp_version = val;
-			return 0;
+			break;
 		default:
 			return -EINVAL;
 		}
+		lock_sock(sk);
+		if (po->rx_ring.pg_vec || po->tx_ring.pg_vec) {
+			ret = -EBUSY;
+		} else {
+			po->tp_version = val;
+			ret = 0;
+		}
+		release_sock(sk);
+		return ret;
 	}
 	case PACKET_RESERVE:
 	{
@@ -4164,6 +4170,7 @@ static int packet_set_ring(struct sock *sk, union tpacket_req_u *req_u,
 	/* Added to avoid minimal code churn */
 	struct tpacket_req *req = &req_u->req;
 
+	lock_sock(sk);
 	/* Opening a Tx-ring is NOT supported in TPACKET_V3 */
 	if (!closing && tx_ring && (po->tp_version > TPACKET_V2)) {
 		net_warn_ratelimited("Tx-ring is not supported.\n");
@@ -4245,7 +4252,6 @@ static int packet_set_ring(struct sock *sk, union tpacket_req_u *req_u,
 			goto out;
 	}
 
-	lock_sock(sk);
 
 	/* Detach socket from network */
 	spin_lock(&po->bind_lock);
@@ -4294,11 +4300,11 @@ static int packet_set_ring(struct sock *sk, union tpacket_req_u *req_u,
 		if (!tx_ring)
 			prb_shutdown_retire_blk_timer(po, rb_queue);
 	}
-	release_sock(sk);
 
 	if (pg_vec)
 		free_pg_vec(pg_vec, order, req->tp_block_nr);
 out:
+	release_sock(sk);
 	return err;
 }
 
-- 
cgit v0.12

