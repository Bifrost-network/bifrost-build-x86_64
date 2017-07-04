--- drivers/net/ethernet/intel/ixgbe/ixgbe_main.c.orig	Tue Jul  4 09:26:13 2017
+++ drivers/net/ethernet/intel/ixgbe/ixgbe_main.c	Tue Jul  4 09:32:51 2017
@@ -3728,13 +3728,15 @@
 	u32 i, j;
 	u32 reta_entries = ixgbe_rss_indir_tbl_entries(adapter);
 	u16 rss_i = adapter->ring_feature[RING_F_RSS].indices;
-
+	int rss_start = 0;
+	if(rss_i > 1) rss_start = 1;
+	
 	/* Program table for at least 4 queues w/ SR-IOV so that VFs can
 	 * make full use of any rings they may have.  We will use the
 	 * PSRTYPE register to control how many rings we use within the PF.
 	 */
 	if ((adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) && (rss_i < 4))
-		rss_i = 4;
+		rss_i = 4 + rss_start;
 
 	/* Fill out hash function seeds */
 	ixgbe_store_key(adapter);
@@ -3742,9 +3744,9 @@
 	/* Fill out redirection table */
 	memset(adapter->rss_indir_tbl, 0, sizeof(adapter->rss_indir_tbl));
 
-	for (i = 0, j = 0; i < reta_entries; i++, j++) {
+	for (i = 0, j = rss_start; i < reta_entries; i++, j++) {
 		if (j == rss_i)
-			j = 0;
+			j = rss_start;
 
 		adapter->rss_indir_tbl[i] = j;
 	}
