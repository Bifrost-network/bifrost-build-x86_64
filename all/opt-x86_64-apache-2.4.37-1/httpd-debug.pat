diff -ur httpd-2.4.10.orig/modules/proxy/mod_proxy_balancer.c httpd-2.4.10/modules/proxy/mod_proxy_balancer.c
--- httpd-2.4.10.orig/modules/proxy/mod_proxy_balancer.c	2014-06-17 14:06:05.000000000 +0200
+++ httpd-2.4.10/modules/proxy/mod_proxy_balancer.c	2014-10-22 09:29:05.403105854 +0200
@@ -218,6 +218,7 @@
             if ( (checking_standby ? !PROXY_WORKER_IS_STANDBY(worker) : PROXY_WORKER_IS_STANDBY(worker)) )
                 continue;
             if (*(worker->s->route) && strcmp(worker->s->route, route) == 0) {
+		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: possible worker %s", worker->s->name);
                 if (PROXY_WORKER_IS_USABLE(worker)) {
                     return worker;
                 } else {
@@ -263,6 +265,7 @@
         }
         checked_standby = checking_standby++;
     }
+    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: find_route_worker failed for %s", route);
     return NULL;
 }
 
@@ -318,8 +323,9 @@
         }
         return worker;
     }
-    else
-        return NULL;
+    else {
+	    return NULL;
+    }
 }
 
 static proxy_worker *find_best_worker(proxy_balancer *balancer,
@@ -337,8 +343,10 @@
 
     candidate = (*balancer->lbmethod->finder)(balancer, r);
 
-    if (candidate)
+    if (candidate) {
         candidate->s->elected++;
+	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: candidate found and elected");
+    }
 
     if ((rv = PROXY_THREAD_UNLOCK(balancer)) != APR_SUCCESS) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01164)
@@ -354,6 +362,7 @@
          * By default the timeout is not set, and the server
          * returns SERVER_BUSY.
          */
+	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: NO candidate found");
         if (balancer->s->timeout) {
             /* XXX: This can perhaps be build using some
              * smarter mechanism, like tread_cond.
@@ -489,6 +498,10 @@
 
     /* Step 4: find the session route */
     runtime = find_session_route(*balancer, r, &route, &sticky, url);
+    if(runtime) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: runtime %s", runtime->s->name);
+    if(route) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: route %s", route);
+    if(sticky) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: sticky %s", sticky);
+
     if (runtime) {
         if ((*balancer)->lbmethod && (*balancer)->lbmethod->updatelbstatus) {
             /* Call the LB implementation */
@@ -527,6 +540,7 @@
          * balancer name. See if the provider route is the
          * member of the same balancer in which case return 503
          */
+	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: runtime is null for %s", route);
         workers = (proxy_worker **)(*balancer)->workers->elts;
         for (i = 0; i < (*balancer)->workers->nelts; i++) {
             if (*((*workers)->s->route) && strcmp((*workers)->s->route, route) == 0) {
@@ -554,6 +568,7 @@
                       (*balancer)->s->name);
     }
     if (!*worker) {
+	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: try find_best_worker");
         runtime = find_best_worker(*balancer, r);
         if (!runtime) {
             if ((*balancer)->workers->nelts) {
@@ -577,6 +592,7 @@
              * balancer where we can send the request. Thus notice that we have
              * changed the route to the backend.
              */
+		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "JEL: balancer route changed to %s", runtime->s->name);
             apr_table_setn(r->subprocess_env, "BALANCER_ROUTE_CHANGED", "1");
         }
         *worker = runtime;
Only in httpd-2.4.10/modules/proxy: mod_proxy_balancer.c~
