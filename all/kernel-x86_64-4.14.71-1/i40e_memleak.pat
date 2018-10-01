From 2b9478ffc550f17c6cd8c69057234e91150f5972 Mon Sep 17 00:00:00 2001
From: Alexander Duyck <alexander.h.duyck@intel.com>
Date: Wed, 4 Oct 2017 08:44:43 -0700
Subject: i40e: Fix memory leak related filter programming status

It looks like we weren't correctly placing the pages from buffers that had
been used to return a filter programming status back on the ring. As a
result they were being overwritten and tracking of the pages was lost.

This change works to correct that by incorporating part of
i40e_put_rx_buffer into the programming status handler code. As a result we
should now be correctly placing the pages for those buffers on the
re-allocation list instead of letting them stay in place.

Fixes: 0e626ff7ccbf ("i40e: Fix support for flow director programming status")
Reported-by: Anders K. Pedersen <akp@cohaesio.com>
Signed-off-by: Alexander Duyck <alexander.h.duyck@intel.com>
Tested-by: Anders K Pedersen <akp@cohaesio.com>
Signed-off-by: Jeff Kirsher <jeffrey.t.kirsher@intel.com>
---
 drivers/net/ethernet/intel/i40e/i40e_txrx.c | 63 ++++++++++++++++-------------
 1 file changed, 36 insertions(+), 27 deletions(-)

(limited to 'drivers/net/ethernet/intel/i40e/i40e_txrx.c')

diff --git a/drivers/net/ethernet/intel/i40e/i40e_txrx.c b/drivers/net/ethernet/intel/i40e/i40e_txrx.c
index 1519dfb..2756131 100644
--- a/drivers/net/ethernet/intel/i40e/i40e_txrx.c
+++ b/drivers/net/ethernet/intel/i40e/i40e_txrx.c
@@ -1038,6 +1038,32 @@ reset_latency:
 }
 
 /**
+ * i40e_reuse_rx_page - page flip buffer and store it back on the ring
+ * @rx_ring: rx descriptor ring to store buffers on
+ * @old_buff: donor buffer to have page reused
+ *
+ * Synchronizes page for reuse by the adapter
+ **/
+static void i40e_reuse_rx_page(struct i40e_ring *rx_ring,
+			       struct i40e_rx_buffer *old_buff)
+{
+	struct i40e_rx_buffer *new_buff;
+	u16 nta = rx_ring->next_to_alloc;
+
+	new_buff = &rx_ring->rx_bi[nta];
+
+	/* update, and store next to alloc */
+	nta++;
+	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;
+
+	/* transfer page from old buffer to new buffer */
+	new_buff->dma		= old_buff->dma;
+	new_buff->page		= old_buff->page;
+	new_buff->page_offset	= old_buff->page_offset;
+	new_buff->pagecnt_bias	= old_buff->pagecnt_bias;
+}
+
+/**
  * i40e_rx_is_programming_status - check for programming status descriptor
  * @qw: qword representing status_error_len in CPU ordering
  *
@@ -1071,15 +1097,24 @@ static void i40e_clean_programming_status(struct i40e_ring *rx_ring,
 					  union i40e_rx_desc *rx_desc,
 					  u64 qw)
 {
-	u32 ntc = rx_ring->next_to_clean + 1;
+	struct i40e_rx_buffer *rx_buffer;
+	u32 ntc = rx_ring->next_to_clean;
 	u8 id;
 
 	/* fetch, update, and store next to clean */
+	rx_buffer = &rx_ring->rx_bi[ntc++];
 	ntc = (ntc < rx_ring->count) ? ntc : 0;
 	rx_ring->next_to_clean = ntc;
 
 	prefetch(I40E_RX_DESC(rx_ring, ntc));
 
+	/* place unused page back on the ring */
+	i40e_reuse_rx_page(rx_ring, rx_buffer);
+	rx_ring->rx_stats.page_reuse_count++;
+
+	/* clear contents of buffer_info */
+	rx_buffer->page = NULL;
+
 	id = (qw & I40E_RX_PROG_STATUS_DESC_QW1_PROGID_MASK) >>
 		  I40E_RX_PROG_STATUS_DESC_QW1_PROGID_SHIFT;
 
@@ -1639,32 +1674,6 @@ static bool i40e_cleanup_headers(struct i40e_ring *rx_ring, struct sk_buff *skb,
 }
 
 /**
- * i40e_reuse_rx_page - page flip buffer and store it back on the ring
- * @rx_ring: rx descriptor ring to store buffers on
- * @old_buff: donor buffer to have page reused
- *
- * Synchronizes page for reuse by the adapter
- **/
-static void i40e_reuse_rx_page(struct i40e_ring *rx_ring,
-			       struct i40e_rx_buffer *old_buff)
-{
-	struct i40e_rx_buffer *new_buff;
-	u16 nta = rx_ring->next_to_alloc;
-
-	new_buff = &rx_ring->rx_bi[nta];
-
-	/* update, and store next to alloc */
-	nta++;
-	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;
-
-	/* transfer page from old buffer to new buffer */
-	new_buff->dma		= old_buff->dma;
-	new_buff->page		= old_buff->page;
-	new_buff->page_offset	= old_buff->page_offset;
-	new_buff->pagecnt_bias	= old_buff->pagecnt_bias;
-}
-
-/**
  * i40e_page_is_reusable - check if any reuse is possible
  * @page: page struct to check
  *
-- 
cgit v1.1

