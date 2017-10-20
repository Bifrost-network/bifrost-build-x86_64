--- httpd/httpd/trunk/modules/proxy/mod_proxy.c	2017/08/16 13:40:59	1805194
+++ httpd/httpd/trunk/modules/proxy/mod_proxy.c	2017/08/16 13:41:39	1805195
@@ -108,7 +108,7 @@
          */
         double fval = atof(val);
         ival = fval * 100.0;
-        if (ival < 1 || ival > 100)
+        if (ival < 100 || ival > 10000)
             return "LoadFactor must be a number between 1..100";
         worker->s->lbfactor = ival;
     }
