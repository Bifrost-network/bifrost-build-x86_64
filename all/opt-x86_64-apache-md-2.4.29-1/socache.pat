--- httpd-2.4.27.orig/modules/cache/mod_cache_socache.c	2017-06-29 13:31:20.000000000 +0200
+++ httpd-2.4.27/modules/cache/mod_cache_socache.c	2017-08-24 15:42:54.000000000 +0200
@@ -384,6 +384,7 @@
      * decide whether or not to ignore this attempt to cache,
      * with a small margin just to be sure.
      */
+#if 0
     if (len < 0) {
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02346)
                 "URL '%s' had no explicit size, ignoring", key);
@@ -416,7 +417,7 @@
                 key, len, dconf->max);
         return DECLINED;
     }
-
+#endif
     /* Allocate and initialize cache_object_t and cache_socache_object_t */
     h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
     obj->vobj = sobj = apr_pcalloc(r->pool, sizeof(*sobj));
@@ -1016,6 +1017,18 @@
             continue;
         }
 
+	if((sobj->body_offset+sobj->body_length+length) > dconf->max) {
+		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
+			      "URL %s, %" APR_OFF_T_FMT " too large for cache. max=%" APR_OFF_T_FMT,
+			      h->cache_obj->key,
+			      sobj->body_offset+sobj->body_length+length,
+			      dconf->max
+			);
+		apr_pool_destroy(sobj->pool);
+		sobj->pool = NULL;
+		continue;
+	}
+
         sobj->body_length += length;
         if (sobj->body_length >= sobj->buffer_len - sobj->body_offset) {
             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02378)
@@ -1090,6 +1103,12 @@
     cache_socache_object_t *sobj = (cache_socache_object_t *) obj->vobj;
     apr_status_t rv;
 
+    if(!sobj->pool) {
+	    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Not caching: %s",
+			  sobj->key);
+	    return DECLINED;
+    }
+
     if (socache_mutex) {
         apr_status_t status = apr_global_mutex_lock(socache_mutex);
         if (status != APR_SUCCESS) {
