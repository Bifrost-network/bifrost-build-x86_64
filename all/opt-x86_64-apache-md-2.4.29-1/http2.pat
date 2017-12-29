--- a/modules/http2/h2_workers.c
+++ b/modules/http2/h2_workers.c
@@ -305,7 +305,18 @@ h2_workers *h2_workers_create(server_rec *s, apr_pool_t *server_pool,
     workers->max_workers = max_workers;
     workers->max_idle_secs = (idle_secs > 0)? idle_secs : 10;
 
-    status = h2_fifo_create(&workers->mplxs, pool, 2 * workers->max_workers);
+    /* FIXME: the fifo set we use here has limited capacity. Once the
+     * set is full, connections with new requests do a wait. Unfortunately,
+     * we have optimizations in place there that makes such waiting "unfair"
+     * in the sense that it may take connections a looong time to get scheduled.
+     *
+     * Need to rewrite this to use one of our double-linked lists and a mutex
+     * to have unlimited capacity and fair scheduling.
+     *
+     * For now, we just make enough room to have many connections inside one
+     * process.
+     */
+    status = h2_fifo_set_create(&workers->mplxs, pool, 8 * 1024);
     if (status != APR_SUCCESS) {
         return NULL;
     }
