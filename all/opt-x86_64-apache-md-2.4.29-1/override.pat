diff -ur httpd-2.4.28.orig//modules/proxy/mod_proxy.c httpd-2.4.28/modules/proxy/mod_proxy.c
--- httpd-2.4.28.orig//modules/proxy/mod_proxy.c	2017-09-19 12:17:40.000000000 +0200
+++ httpd-2.4.28/modules/proxy/mod_proxy.c	2017-10-12 08:49:50.000000000 +0200
@@ -1452,6 +1452,7 @@
     new->interpolate_env = -1; /* unset */
     new->error_override = 0;
     new->error_override_set = 0;
+    new->error_override_codes = (void*)0;
     new->add_forwarded_headers = 1;
     new->add_forwarded_headers_set = 0;
 
@@ -1483,6 +1484,8 @@
     new->error_override = (add->error_override_set == 0) ? base->error_override
                                                         : add->error_override;
     new->error_override_set = add->error_override_set || base->error_override_set;
+    new->error_override_codes = (add->error_override_set == 0) ? base->error_override_codes
+	                                                      : add->error_override_codes;
     new->alias = (add->alias_set == 0) ? base->alias : add->alias;
     new->alias_set = add->alias_set || base->alias_set;
     new->add_forwarded_headers =
@@ -1965,9 +1968,42 @@
 }
 
 static const char *
-    set_proxy_error_override(cmd_parms *parms, void *dconf, int flag)
+set_proxy_error_override(cmd_parms *parms, void *dconf, const char *flagstr, const char *codes)
 {
     proxy_dir_conf *conf = dconf;
+    int flag = -1;
+
+    if(!strcasecmp(flagstr, "on")) {
+	    flag = 1;
+    }
+    if(!strcasecmp(flagstr, "off")) {
+	    flag = 0;
+    }
+    if(flag == -1) {
+	    return "ProxyErrorOverride flag must be On or Off";
+    }
+
+    if(codes) {
+	    char *val;
+	    char *code_state;
+	    char *code;
+	    int ival;
+	    
+	    val = apr_pstrdup(parms->pool, codes);
+	    conf->error_override_codes = apr_array_make(parms->pool, 1, sizeof(int));
+
+	    code = apr_strtok(val, ", ", &code_state);
+	    while (code != NULL) {
+		    ival = atoi(code);
+		    if (ap_is_HTTP_VALID_RESPONSE(ival)) {
+			    *(int *)apr_array_push(conf->error_override_codes) = ival;
+		    }
+		    else {
+			    return "ProxyErrorOverride codes must be one or more HTTP response codes";
+		    }
+		    code = apr_strtok(NULL, ", ", &code_state);
+	    }
+    }
 
     conf->error_override = flag;
     conf->error_override_set = 1;
@@ -2525,7 +2561,7 @@
      "The default intranet domain name (in absence of a domain in the URL)"),
     AP_INIT_TAKE1("ProxyVia", set_via_opt, NULL, RSRC_CONF,
      "Configure Via: proxy header header to one of: on | off | block | full"),
-    AP_INIT_FLAG("ProxyErrorOverride", set_proxy_error_override, NULL, RSRC_CONF|ACCESS_CONF,
+    AP_INIT_TAKE12("ProxyErrorOverride", set_proxy_error_override, NULL, RSRC_CONF|ACCESS_CONF,
      "use our error handling pages instead of the servers' we are proxying"),
     AP_INIT_FLAG("ProxyPreserveHost", set_preserve_host, NULL, RSRC_CONF|ACCESS_CONF,
      "on if we should preserve host header while proxying"),
Only in httpd-2.4.28/modules/proxy: mod_proxy.c.orig
diff -ur httpd-2.4.28.orig//modules/proxy/mod_proxy.h httpd-2.4.28/modules/proxy/mod_proxy.h
--- httpd-2.4.28.orig//modules/proxy/mod_proxy.h	2017-08-18 10:49:42.000000000 +0200
+++ httpd-2.4.28/modules/proxy/mod_proxy.h	2017-10-12 08:49:50.000000000 +0200
@@ -237,6 +237,8 @@
     unsigned int add_forwarded_headers:1;
     unsigned int add_forwarded_headers_set:1;
 
+    apr_array_header_t *error_override_codes;
+
     /** Named back references */
     apr_array_header_t *refs;
 
Only in httpd-2.4.28/modules/proxy: mod_proxy.h.orig
diff -ur httpd-2.4.28.orig//modules/proxy/mod_proxy_ajp.c httpd-2.4.28/modules/proxy/mod_proxy_ajp.c
--- httpd-2.4.28.orig//modules/proxy/mod_proxy_ajp.c	2016-10-24 12:06:41.000000000 +0200
+++ httpd-2.4.28/modules/proxy/mod_proxy_ajp.c	2017-10-12 08:49:50.000000000 +0200
@@ -193,6 +193,7 @@
     apr_off_t content_length = 0;
     int original_status = r->status;
     const char *original_status_line = r->status_line;
+    int error_override = 0;
 
     if (psf->io_buffer_size_set)
        maxsize = psf->io_buffer_size;
@@ -449,17 +450,35 @@
                 if (status != APR_SUCCESS) {
                     backend_failed = 1;
                 }
-                else if ((r->status == 401) && conf->error_override) {
-                    const char *buf;
-                    const char *wa = "WWW-Authenticate";
-                    if ((buf = apr_table_get(r->headers_out, wa))) {
-                        apr_table_set(r->err_headers_out, wa, buf);
-                    } else {
-                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00885)
-                                      "ap_proxy_ajp_request: origin server "
-                                      "sent 401 without WWW-Authenticate header");
-                    }
-                }
+                else { 
+			/* Determine if error_override should be set */
+			if(conf->error_override) {
+				if(conf->error_override_codes) {
+					int i;
+					for (i = 0; i < conf->error_override_codes->nelts; i++) {
+						int val = ((int *)conf->error_override_codes->elts)[i];
+						if (r->status == val) {
+							error_override = 1;
+							break;
+						}
+					}
+				} else {
+					error_override = 1;
+				}
+			}
+			
+			if ((r->status == 401) && error_override) {
+				const char *buf;
+				const char *wa = "WWW-Authenticate";
+				if ((buf = apr_table_get(r->headers_out, wa))) {
+					apr_table_set(r->err_headers_out, wa, buf);
+				} else {
+					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00885)
+						      "ap_proxy_ajp_request: origin server "
+						      "sent 401 without WWW-Authenticate header");
+				}
+			}
+		}
                 headers_sent = 1;
                 break;
             case CMD_AJP13_SEND_BODY_CHUNK:
@@ -469,7 +488,7 @@
                     /* If we are overriding the errors, we can't put the content
                      * of the page into the brigade.
                      */
-                    if (!conf->error_override || !ap_is_HTTP_ERROR(r->status)) {
+                    if (!error_override || !ap_is_HTTP_ERROR(r->status)) {
                         /* AJP13_SEND_BODY_CHUNK with zero length
                          * is explicit flush message
                          */
@@ -492,7 +511,7 @@
                              * error status so that an underlying error (eg HTTP_NOT_FOUND)
                              * doesn't become an HTTP_OK.
                              */
-                            if (conf->error_override && !ap_is_HTTP_ERROR(r->status)
+                            if (error_override && !ap_is_HTTP_ERROR(r->status)
                                     && ap_is_HTTP_ERROR(original_status)) {
                                 r->status = original_status;
                                 r->status_line = original_status_line;
@@ -542,7 +561,7 @@
                 if (status != APR_SUCCESS) {
                     backend_failed = 1;
                 }
-                if (!conf->error_override || !ap_is_HTTP_ERROR(r->status)) {
+                if (!error_override || !ap_is_HTTP_ERROR(r->status)) {
                     e = apr_bucket_eos_create(r->connection->bucket_alloc);
                     APR_BRIGADE_INSERT_TAIL(output_brigade, e);
                     if (ap_pass_brigade(r->output_filters,
@@ -637,7 +656,7 @@
                       conn->worker->cp->addr,
                       conn->worker->s->hostname);
 
-        if (conf->error_override && ap_is_HTTP_ERROR(r->status)) {
+        if (error_override && ap_is_HTTP_ERROR(r->status)) {
             /* clear r->status for override error, otherwise ErrorDocument
              * thinks that this is a recursive error, and doesn't find the
              * custom error page
Only in httpd-2.4.28/modules/proxy: mod_proxy_ajp.c.orig
diff -ur httpd-2.4.28.orig//modules/proxy/mod_proxy_http.c httpd-2.4.28/modules/proxy/mod_proxy_http.c
--- httpd-2.4.28.orig//modules/proxy/mod_proxy_http.c	2016-10-24 12:06:41.000000000 +0200
+++ httpd-2.4.28/modules/proxy/mod_proxy_http.c	2017-10-12 08:49:50.000000000 +0200
@@ -1209,6 +1209,7 @@
     apr_interval_time_t old_timeout = 0;
     proxy_dir_conf *dconf;
     int do_100_continue;
+    int error_override = 0;
 
     dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
 
@@ -1551,7 +1552,24 @@
          * ProxyPassReverse/etc from here to ap_proxy_read_headers
          */
 
-        if ((proxy_status == 401) && (dconf->error_override)) {
+	/* Determine if error_override should be set */
+	if(dconf->error_override) {
+		if(dconf->error_override_codes) {
+			int i;
+			for (i = 0; i < dconf->error_override_codes->nelts; i++) {
+				int val = ((int *)dconf->error_override_codes->elts)[i];
+				if (proxy_status == val) {
+					error_override = 1;
+					break;
+				}
+			}
+		} else {
+			error_override = 1;
+		}
+	}
+
+
+        if ((proxy_status == 401) && (error_override)) {
             const char *buf;
             const char *wa = "WWW-Authenticate";
             if ((buf = apr_table_get(r->headers_out, wa))) {
@@ -1589,7 +1607,7 @@
             APR_BRIGADE_INSERT_TAIL(bb, e);
         }
         /* PR 41646: get HEAD right with ProxyErrorOverride */
-        if (ap_is_HTTP_ERROR(r->status) && dconf->error_override) {
+        if (ap_is_HTTP_ERROR(r->status) && error_override) {
             /* clear r->status for override error, otherwise ErrorDocument
              * thinks that this is a recursive error, and doesn't find the
              * custom error page
@@ -1650,7 +1668,7 @@
              * if we are overriding the errors, we can't put the content
              * of the page into the brigade
              */
-            if (!dconf->error_override || !ap_is_HTTP_ERROR(proxy_status)) {
+            if (!error_override || !ap_is_HTTP_ERROR(proxy_status)) {
                 /* read the body, pass it to the output filters */
                 apr_read_type_e mode = APR_NONBLOCK_READ;
                 int finish = FALSE;
@@ -1660,7 +1678,7 @@
                  * error status so that an underlying error (eg HTTP_NOT_FOUND)
                  * doesn't become an HTTP_OK.
                  */
-                if (dconf->error_override && !ap_is_HTTP_ERROR(proxy_status)
+                if (error_override && !ap_is_HTTP_ERROR(proxy_status)
                         && ap_is_HTTP_ERROR(original_status)) {
                     r->status = original_status;
                     r->status_line = original_status_line;
Only in httpd-2.4.28/modules/proxy: mod_proxy_http.c.orig
