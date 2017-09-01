/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_vhost.h>

#include "md.h"
#include "md_util.h"
#include "mod_md_private.h"
#include "mod_md_config.h"

#define MD_CMD_MD             "ManagedDomain"
#define MD_CMD_MD_SECTION     "<ManagedDomain"
#define MD_CMD_CA             "MDCertificateAuthority"
#define MD_CMD_CAAGREEMENT    "MDCertificateAgreement"
#define MD_CMD_CACHALLENGES   "MDCAChallenges"
#define MD_CMD_CAPROTO        "MDCertificateProtocol"
#define MD_CMD_DRIVEMODE      "MDDriveMode"
#define MD_CMD_MEMBER         "MDMember"
#define MD_CMD_MEMBERS        "MDMembers"
#define MD_CMD_PORTMAP        "MDPortMap"
#define MD_CMD_RENEWWINDOW    "MDRenewWindow"
#define MD_CMD_STOREDIR       "MDStoreDir"

#define DEF_VAL     (-1)

/* Default settings for the global conf */
static md_mod_conf_t defmc = {
    NULL,
    "md",
    NULL,
    80,
    443,
    0,
    0,
    NULL
};

/* Default server specific setting */
static md_srv_conf_t defconf = {
    "default",
    NULL,
    &defmc,

    1,
    MD_DRIVE_AUTO,
    0,
    apr_time_from_sec(14 * MD_SECS_PER_DAY),

    MD_ACME_DEF_URL,
    "ACME",
    NULL,
    NULL,
    NULL,
    NULL,
};

static md_mod_conf_t *mod_md_config;

static apr_status_t cleanup_mod_config(void *dummy)
{
    (void)dummy;
    mod_md_config = NULL;
    return APR_SUCCESS;
}

static md_mod_conf_t *md_mod_conf_get(apr_pool_t *pool, int create)
{
    if (mod_md_config) {
        return mod_md_config; /* reused for lifetime of the pool */
    }

    if (create) {
        mod_md_config = apr_pcalloc(pool, sizeof(*mod_md_config));
        memcpy(mod_md_config, &defmc, sizeof(*mod_md_config));
        mod_md_config->mds = apr_array_make(pool, 5, sizeof(const md_t *));
        mod_md_config->unused_names = apr_array_make(pool, 5, sizeof(const md_t *));
        
        apr_pool_cleanup_register(pool, NULL, cleanup_mod_config, apr_pool_cleanup_null);
    }
    
    return mod_md_config;
}

#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

static void srv_conf_props_clear(md_srv_conf_t *sc)
{
    sc->transitive = DEF_VAL;
    sc->drive_mode = DEF_VAL;
    sc->must_staple = DEF_VAL;
    sc->renew_window = DEF_VAL;
    sc->ca_url = NULL;
    sc->ca_proto = NULL;
    sc->ca_agreement = NULL;
    sc->ca_challenges = NULL;
}

static void srv_conf_props_copy(md_srv_conf_t *to, const md_srv_conf_t *from)
{
    to->transitive = from->transitive;
    to->drive_mode = from->drive_mode;
    to->must_staple = from->must_staple;
    to->renew_window = from->renew_window;
    to->ca_url = from->ca_url;
    to->ca_proto = from->ca_proto;
    to->ca_agreement = from->ca_agreement;
    to->ca_challenges = from->ca_challenges;
}

static void srv_conf_props_apply(md_t *md, const md_srv_conf_t *from, apr_pool_t *p)
{
    if (from->transitive != DEF_VAL) md->transitive = from->transitive;
    if (from->drive_mode != DEF_VAL) md->drive_mode = from->drive_mode;
    if (from->must_staple != DEF_VAL) md->must_staple = from->must_staple;
    if (from->renew_window != DEF_VAL) md->renew_window = from->renew_window;

    if (from->ca_url) md->ca_url = from->ca_url;
    if (from->ca_proto) md->ca_proto = from->ca_proto;
    if (from->ca_agreement) md->ca_agreement = from->ca_agreement;
    if (from->ca_challenges) md->ca_challenges = apr_array_copy(p, from->ca_challenges);
}

void *md_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    md_srv_conf_t *conf = (md_srv_conf_t *)apr_pcalloc(pool, sizeof(md_srv_conf_t));

    conf->name = apr_pstrcat(pool, "srv[", CONF_S_NAME(s), "]", NULL);
    conf->s = s;
    conf->mc = md_mod_conf_get(pool, 1);

    srv_conf_props_clear(conf);
    
    return conf;
}

static void *md_config_merge(apr_pool_t *pool, void *basev, void *addv)
{
    md_srv_conf_t *base = (md_srv_conf_t *)basev;
    md_srv_conf_t *add = (md_srv_conf_t *)addv;
    md_srv_conf_t *nsc;
    char *name = apr_pstrcat(pool, "[", CONF_S_NAME(add->s), ", ", CONF_S_NAME(base->s), "]", NULL);
    
    nsc = (md_srv_conf_t *)apr_pcalloc(pool, sizeof(md_srv_conf_t));
    nsc->name = name;

    nsc->transitive = (add->transitive != DEF_VAL)? add->transitive : base->transitive;
    nsc->drive_mode = (add->drive_mode != DEF_VAL)? add->drive_mode : base->drive_mode;
    nsc->renew_window = (add->renew_window != DEF_VAL)? add->renew_window : base->renew_window;

    nsc->ca_url = add->ca_url? add->ca_url : base->ca_url;
    nsc->ca_proto = add->ca_proto? add->ca_proto : base->ca_proto;
    nsc->ca_agreement = add->ca_agreement? add->ca_agreement : base->ca_agreement;
    nsc->ca_challenges = (add->ca_challenges? apr_array_copy(pool, add->ca_challenges) 
                    : (base->ca_challenges? apr_array_copy(pool, base->ca_challenges) : NULL));
    nsc->current = NULL;
    nsc->assigned = NULL;
    
    return nsc;
}

void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    return md_config_merge(pool, basev, addv);
}

static int inside_section(cmd_parms *cmd, const char *section) {
    ap_directive_t *d;
    for (d = cmd->directive->parent; d; d = d->parent) {
       if (!ap_cstr_casecmp(d->directive, section)) {
           return 1;
       }
    }
    return 0; 
}

static const char *md_section_check(cmd_parms *cmd, const char *section) {
    if (!inside_section(cmd, section)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " is only valid inside a '", 
                           section, "' context, not here", NULL);
    }
    return NULL;
}

static void add_domain_name(apr_array_header_t *domains, const char *name, apr_pool_t *p)
{
    if (md_array_str_index(domains, name, 0, 0) < 0) {
        APR_ARRAY_PUSH(domains, char *) = md_util_str_tolower(apr_pstrdup(p, name));
    }
}

static const char *set_transitive(int *ptransitive, const char *value)
{
    if (!apr_strnatcasecmp("auto", value)) {
        *ptransitive = 1;
        return NULL;
    }
    else if (!apr_strnatcasecmp("manual", value)) {
        *ptransitive = 0;
        return NULL;
    }
    return "unknown value, use \"auto|manual\"";
}

static const char *md_config_sec_start(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc;
    md_srv_conf_t save;
    const char *endp;
    const char *err, *name;
    apr_array_header_t *domains;
    md_t *md;
    int transitive = -1;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
        
    sc = md_config_get(cmd->server);
    endp = ap_strrchr_c(arg, '>');
    if (endp == NULL) {
        return  MD_CMD_MD_SECTION "> directive missing closing '>'";
    }

    arg = apr_pstrndup(cmd->pool, arg, endp-arg);
    if (!arg || !*arg) {
        return MD_CMD_MD_SECTION " > section must specify a unique domain name";
    }

    name = ap_getword_white(cmd->pool, &arg);
    domains = apr_array_make(cmd->pool, 5, sizeof(const char *));
    add_domain_name(domains, name, cmd->pool);
    while (*arg != '\0') {
        name = ap_getword_white(cmd->pool, &arg);
        if (NULL != set_transitive(&transitive, name)) {
            add_domain_name(domains, name, cmd->pool);
        }
    }

    if (domains->nelts == 0) {
        return "needs at least one domain name";
    }
    
    md = md_create(cmd->pool, domains);
    if (transitive >= 0) {
        md->transitive = transitive;
    }
    
    /* Save the current settings in this srv_conf and apply+restore at the
     * end of this section */
    memcpy(&save, sc, sizeof(save));
    srv_conf_props_clear(sc);
    sc->current = md;
    
    if (NULL == (err = ap_walk_config(cmd->directive->first_child, cmd, cmd->context))) {
        srv_conf_props_apply(md, sc, cmd->pool);
        APR_ARRAY_PUSH(sc->mc->mds, const md_t *) = md;
    }
    
    sc->current = NULL;
    srv_conf_props_copy(sc, &save);
    
    return err;
}

static const char *md_config_sec_add_members(cmd_parms *cmd, void *dc, 
                                             int argc, char *const argv[])
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;
    int i;
    
    if (NULL != (err = md_section_check(cmd, MD_CMD_MD_SECTION))) {
        if (argc == 1) {
            /* only these values are allowed outside a section */
            return set_transitive(&sc->transitive, argv[0]);
        }
        return err;
    }
    
    assert(sc->current);
    for (i = 0; i < argc; ++i) {
        if (NULL != set_transitive(&sc->transitive, argv[i])) {
            add_domain_name(sc->current->domains, argv[i], cmd->pool);
        }
    }
    return NULL;
}

static const char *md_config_set_names(cmd_parms *cmd, void *arg, 
                                       int argc, char *const argv[])
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    apr_array_header_t *domains = apr_array_make(cmd->pool, 5, sizeof(const char *));
    const char *err;
    md_t *md;
    int i, transitive = -1;

    err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err) {
        return err;
    }

    for (i = 0; i < argc; ++i) {
        if (NULL != set_transitive(&transitive, argv[i])) {
            add_domain_name(domains, argv[i], cmd->pool);
        }
    }
    
    if (domains->nelts == 0) {
        return "needs at least one domain name";
    }
    md = md_create(cmd->pool, domains);

    if (transitive >= 0) {
        md->transitive = transitive;
    }
    
    if (cmd->config_file) {
        md->defn_name = cmd->config_file->name;
        md->defn_line_number = cmd->config_file->line_number;
    }

    APR_ARRAY_PUSH(sc->mc->mds, md_t *) = md;

    return NULL;
}

static const char *md_config_set_ca(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    sc->ca_url = value;
    return NULL;
}

static const char *md_config_set_ca_proto(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->ca_proto = value;
    return NULL;
}

static const char *md_config_set_agreement(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->ca_agreement = value;
    return NULL;
}

static const char *md_config_set_drive_mode(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    md_drive_mode_t drive_mode;

    if (!apr_strnatcasecmp("auto", value) || !apr_strnatcasecmp("automatic", value)) {
        drive_mode = MD_DRIVE_AUTO;
    }
    else if (!apr_strnatcasecmp("always", value)) {
        drive_mode = MD_DRIVE_ALWAYS;
    }
    else if (!apr_strnatcasecmp("manual", value) || !apr_strnatcasecmp("stick", value)) {
        drive_mode = MD_DRIVE_MANUAL;
    }
    else {
        return apr_pstrcat(cmd->pool, "unknown MDDriveMode ", value, NULL);
    }
    
    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->drive_mode = drive_mode;
    return NULL;
}

static apr_status_t duration_parse(const char *value, apr_interval_time_t *ptimeout, 
                                   const char *def_unit)
{
    char *endp;
    long funits = 1;
    apr_status_t rv;
    apr_int64_t n;
    
    n = apr_strtoi64(value, &endp, 10);
    if (errno) {
        return errno;
    }
    if (!endp || !*endp) {
        if (strcmp(def_unit, "d") == 0) {
            def_unit = "s";
            funits = MD_SECS_PER_DAY;
        }
    }
    else if (*endp == 'd') {
        *ptimeout = apr_time_from_sec(n * MD_SECS_PER_DAY);
        return APR_SUCCESS;
    }
    else {
        def_unit = endp;
    }
    rv = ap_timeout_parameter_parse(value, ptimeout, def_unit);
    if (APR_SUCCESS == rv && funits > 1) {
        *ptimeout *= funits;
    }
    return rv;
}

static const char *md_config_set_renew_window(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    apr_interval_time_t timeout;

    /* Inspired by http_core.c */
    if (duration_parse(value, &timeout, "d") != APR_SUCCESS) {
        return "MDRenewWindow has wrong format";
    }
        
    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->renew_window = timeout;
    return NULL;
}

static const char *md_config_set_store_dir(cmd_parms *cmd, void *arg, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }
    sc->mc->base_dir = value;
    (void)arg;
    return NULL;
}

static const char *set_port_map(md_mod_conf_t *mc, const char *value)
{
    int net_port, local_port;
    char *endp;

    net_port = (int)apr_strtoi64(value, &endp, 10);
    if (errno) {
        return "unable to parse first port number";
    }
    if (!endp || *endp != ':') {
        return "no ':' after first port number";
    }
    ++endp;
    if (*endp == '-') {
        local_port = 0;
    }
    else {
        local_port = (int)apr_strtoi64(endp, &endp, 10);
        if (errno) {
            return "unable to parse second port number";
        }
        if (local_port <= 0 || local_port > 65535) {
            return "invalid number for port map, must be in ]0,65535]";
        }
    }
    switch (net_port) {
        case 80:
            mc->local_80 = local_port;
            break;
        case 443:
            mc->local_443 = local_port;
            break;
        default:
            return "mapped port number must be 80 or 443";
    }
    return NULL;
}

static const char *md_config_set_port_map(cmd_parms *cmd, void *arg, 
                                          const char *v1, const char *v2)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    (void)arg;
    if (!err) {
        err = set_port_map(sc->mc, v1);
    }
    if (!err && v2) {
        err = set_port_map(sc->mc, v2);
    }
    return err;
}

static const char *md_config_set_cha_tyes(cmd_parms *cmd, void *dc, 
                                          int argc, char *const argv[])
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    apr_array_header_t **pcha, *ca_challenges;
    const char *err;
    int i;

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    pcha = &config->ca_challenges; 
    
    ca_challenges = *pcha;
    if (!ca_challenges) {
        *pcha = ca_challenges = apr_array_make(cmd->pool, 5, sizeof(const char *));
    }
    for (i = 0; i < argc; ++i) {
        APR_ARRAY_PUSH(ca_challenges, const char *) = argv[i];
    }
    
    return NULL;
}


const command_rec md_cmds[] = {
    AP_INIT_TAKE1(     MD_CMD_CA, md_config_set_ca, NULL, RSRC_CONF, 
                  "URL of CA issueing the certificates"),
    AP_INIT_TAKE1(     MD_CMD_CAAGREEMENT, md_config_set_agreement, NULL, RSRC_CONF, 
                  "URL of CA Terms-of-Service agreement you accept"),
    AP_INIT_TAKE_ARGV( MD_CMD_CACHALLENGES, md_config_set_cha_tyes, NULL, RSRC_CONF, 
                      "A list of challenge types to be used."),
    AP_INIT_TAKE1(     MD_CMD_CAPROTO, md_config_set_ca_proto, NULL, RSRC_CONF, 
                  "Protocol used to obtain/renew certificates"),
    AP_INIT_TAKE1(     MD_CMD_DRIVEMODE, md_config_set_drive_mode, NULL, RSRC_CONF, 
                  "method of obtaining certificates for the managed domain"),
    AP_INIT_TAKE_ARGV( MD_CMD_MD, md_config_set_names, NULL, RSRC_CONF, 
                      "A group of server names with one certificate"),
    AP_INIT_RAW_ARGS(  MD_CMD_MD_SECTION, md_config_sec_start, NULL, RSRC_CONF, 
                     "Container for a manged domain with common settings and certificate."),
    AP_INIT_TAKE_ARGV( MD_CMD_MEMBER, md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE_ARGV( MD_CMD_MEMBERS, md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE12(    MD_CMD_PORTMAP, md_config_set_port_map, NULL, RSRC_CONF, 
                  "Declare the mapped ports 80 and 443 on the local server. E.g. 80:8000 "
                  "to indicate that the server port 8000 is reachable as port 80 from the "
                  "internet. Use 80:- to indicate that port 80 is not reachable from "
                  "the outside."),
    AP_INIT_TAKE1(     MD_CMD_STOREDIR, md_config_set_store_dir, NULL, RSRC_CONF, 
                  "the directory for file system storage of managed domain data."),
    AP_INIT_TAKE1(     MD_CMD_RENEWWINDOW, md_config_set_renew_window, NULL, RSRC_CONF, 
                  "Time length for renewal before certificate expires (defaults to days)"),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};


static md_srv_conf_t *config_get_int(server_rec *s, apr_pool_t *p)
{
    md_srv_conf_t *sc = (md_srv_conf_t *)ap_get_module_config(s->module_config, &md_module);
    ap_assert(sc);
    if (sc->s != s && p) {
        sc = md_config_merge(p, &defconf, sc);
        sc->name = apr_pstrcat(p, CONF_S_NAME(s), sc->name, NULL);
        sc->mc = md_mod_conf_get(p, 1);
        ap_set_module_config(s->module_config, &md_module, sc);
    }
    return sc;
}

md_srv_conf_t *md_config_get(server_rec *s)
{
    return config_get_int(s, NULL);
}

md_srv_conf_t *md_config_get_unique(server_rec *s, apr_pool_t *p)
{
    assert(p);
    return config_get_int(s, p);
}

md_srv_conf_t *md_config_cget(conn_rec *c)
{
    return md_config_get(c->base_server);
}

const char *md_config_gets(const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_CA_URL:
            return sc->ca_url? sc->ca_url : defconf.ca_url;
        case MD_CONFIG_CA_PROTO:
            return sc->ca_proto? sc->ca_proto : defconf.ca_proto;
        case MD_CONFIG_BASE_DIR:
            return sc->mc->base_dir;
        case MD_CONFIG_CA_AGREEMENT:
            return sc->ca_agreement? sc->ca_agreement : defconf.ca_agreement;
        default:
            return NULL;
    }
}

int md_config_geti(const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_DRIVE_MODE:
            return (sc->drive_mode != DEF_VAL)? sc->drive_mode : defconf.drive_mode;
        case MD_CONFIG_LOCAL_80:
            return sc->mc->local_80;
        case MD_CONFIG_LOCAL_443:
            return sc->mc->local_443;
        case MD_CONFIG_TRANSITIVE:
            return (sc->transitive != DEF_VAL)? sc->transitive : defconf.transitive;
        default:
            return 0;
    }
}

apr_interval_time_t md_config_get_interval(const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_RENEW_WINDOW:
            return (sc->renew_window != DEF_VAL)? sc->renew_window : defconf.renew_window;
        default:
            return 0;
    }
}
/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <apr_strings.h>

#include <mpm_common.h>
#include <httpd.h>
#include <http_log.h>
#include <ap_mpm.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef WIN32
#include "mpm_winnt.h"
#endif
#if AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "md_util.h"
#include "mod_md_os.h"

apr_status_t md_try_chown(const char *fname, int uid, int gid, apr_pool_t *p)
{
#if AP_NEED_SET_MUTEX_PERMS
    if (-1 == chown(fname, (uid_t)uid, (gid_t)gid)) {
        apr_status_t rv = APR_FROM_OS_ERROR(errno);
        if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, rv, p, APLOGNO(10082)
                         "Can't change owner of %s", fname);
        }
        return rv;
    }
    return APR_SUCCESS;
#else 
    return APR_ENOTIMPL;
#endif
}

apr_status_t md_make_worker_accessible(const char *fname, apr_pool_t *p)
{
#if AP_NEED_SET_MUTEX_PERMS
    return md_try_chown(fname, ap_unixd_config.user_id, -1, p);
#else 
    return APR_ENOTIMPL;
#endif
}

#ifdef WIN32

apr_status_t md_server_graceful(apr_pool_t *p, server_rec *s)
{
    return APR_ENOTIMPL;
}
 
#else

apr_status_t md_server_graceful(apr_pool_t *p, server_rec *s)
{ 
    apr_status_t rv;
    
    rv = (kill(getppid(), AP_SIG_GRACEFUL) < 0)? APR_ENOTIMPL : APR_SUCCESS;
    ap_log_error(APLOG_MARK, APLOG_TRACE1, errno, NULL, "sent signal to parent");
    return rv;
}

#endif

/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <apr_strings.h>

#include <ap_release.h>
#include <mpm_common.h>
#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>
#include <ap_listen.h>

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_config.h"
#include "mod_md_os.h"
#include "mod_watchdog.h"

static void md_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(md) = {
    STANDARD20_MODULE_STUFF,
    NULL,                 /* func to create per dir config */
    NULL,                 /* func to merge per dir config */
    md_config_create_svr, /* func to create per server config */
    md_config_merge_svr,  /* func to merge per server config */
    md_cmds,              /* command handlers */
    md_hooks
};

static void md_merge_srv(md_t *md, md_srv_conf_t *base_sc, apr_pool_t *p)
{
    if (!md->sc) {
        md->sc = base_sc;
    }

    if (!md->ca_url) {
        md->ca_url = md_config_gets(md->sc, MD_CONFIG_CA_URL);
    }
    if (!md->ca_proto) {
        md->ca_proto = md_config_gets(md->sc, MD_CONFIG_CA_PROTO);
    }
    if (!md->ca_agreement) {
        md->ca_agreement = md_config_gets(md->sc, MD_CONFIG_CA_AGREEMENT);
    }
    if (md->sc->s->server_admin && strcmp(DEFAULT_ADMIN, md->sc->s->server_admin)) {
        apr_array_clear(md->contacts);
        APR_ARRAY_PUSH(md->contacts, const char *) = 
        md_util_schemify(p, md->sc->s->server_admin, "mailto");
    }
    if (md->drive_mode == MD_DRIVE_DEFAULT) {
        md->drive_mode = md_config_geti(md->sc, MD_CONFIG_DRIVE_MODE);
    }
    if (md->renew_window <= 0) {
        md->renew_window = md_config_get_interval(md->sc, MD_CONFIG_RENEW_WINDOW);
    }
    if (md->transitive < 0) {
        md->transitive = md_config_geti(md->sc, MD_CONFIG_TRANSITIVE);
    }
    if (!md->ca_challenges && md->sc->ca_challenges) {
        md->ca_challenges = apr_array_copy(p, md->sc->ca_challenges);
    }        
}

static apr_status_t check_coverage(md_t *md, const char *domain, server_rec *s, apr_pool_t *p)
{
    if (md_contains(md, domain, 0)) {
        return APR_SUCCESS;
    }
    else if (md->transitive) {
        APR_ARRAY_PUSH(md->domains, const char*) = apr_pstrdup(p, domain);
        return APR_SUCCESS;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(10040)
                     "Virtual Host %s:%d matches Managed Domain '%s', but the "
                     "name/alias %s itself is not managed. A requested MD certificate "
                     "will not match ServerName.",
                     s->server_hostname, s->port, md->name, domain);
        return APR_EINVAL;
    }
}

static apr_status_t apply_to_servers(md_t *md, server_rec *base_server, 
                                     apr_pool_t *p, apr_pool_t *ptemp)
{
    server_rec *s;
    request_rec r;
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    apr_status_t rv = APR_SUCCESS, rv2;
    int i, j;
    const char *domain, *name;
    
    sc = md_config_get(base_server);
    mc = sc->mc;
    
    /* Find the (at most one) managed domain for each vhost/base server and
     * remember it at our config for it. 
     * The config is not accepted, if a vhost matches 2 or more managed domains.
     */
    memset(&r, 0, sizeof(r));
    sc = NULL;
    
    /* This MD may apply to 0, 1 or more sever_recs */
    for (s = base_server; s; s = s->next) {
        r.server = s;
        
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char*);
            
            if (ap_matches_request_vhost(&r, domain, s->port)) {
                /* Create a unique md_srv_conf_t record for this server. 
                 * We keep local information here. */
                sc = md_config_get_unique(s, p);
                
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10041)
                             "Server %s:%d matches md %s (config %s)", 
                             s->server_hostname, s->port, md->name, sc->name);
                
                if (sc->assigned == md) {
                    /* already matched via another domain name */
                    goto next_server;
                }
                else if (sc->assigned) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10042)
                                 "conflict: MD %s matches server %s, but MD %s also matches.",
                                 md->name, s->server_hostname, sc->assigned->name);
                    rv = APR_EINVAL;
                    goto next_server;
                }
                
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10043)
                             "Managed Domain %s applies to vhost %s:%d", md->name,
                             s->server_hostname, s->port);
                
                /* If there is a non-default ServerAdmin defined for this vhost, take
                 * that one as contact info */
                if (s->server_admin && strcmp(DEFAULT_ADMIN, s->server_admin)) {
                    apr_array_clear(md->contacts);
                    APR_ARRAY_PUSH(md->contacts, const char *) = 
                    md_util_schemify(p, s->server_admin, "mailto");
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10044)
                                 "Managed Domain %s assigned server admin %s", md->name,
                                 s->server_admin);
                }
                /* remember */
                sc->assigned = md;
                
                /* This server matches a managed domain. If it contains names or
                 * alias that are not in this md, a generated certificate will not match. */
                if (APR_SUCCESS == (rv2 = check_coverage(md, s->server_hostname, s, p))
                    && s->names) {
                    for (j = 0; j < s->names->nelts; ++j) {
                        name = APR_ARRAY_IDX(s->names, j, const char*);
                        if (APR_SUCCESS != (rv2 = check_coverage(md, name, s, p))) {
                            break;
                        }
                    }
                }
                
                if (APR_SUCCESS != rv2) {
                    rv = rv2;
                }
                goto next_server;
            }
        }
    next_server:
        continue;
    }
    
    if (sc == NULL && md->drive_mode != MD_DRIVE_ALWAYS) {
        /* Not an error, but looks suspicious */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(10045)
                     "No VirtualHost matches Managed Domain %s", md->name);
        APR_ARRAY_PUSH(mc->unused_names, const char*)  = md->name;
    }
    return rv;
}

static apr_status_t md_calc_md_list(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *base_server)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    md_t *md, *omd;
    const char *domain;
    apr_status_t rv = APR_SUCCESS;
    ap_listen_rec *lr;
    apr_sockaddr_t *sa;
    int i, j;

    sc = md_config_get(base_server);
    mc = sc->mc;
    
    mc->can_http = 0;
    mc->can_https = 0;

    for (lr = ap_listeners; lr; lr = lr->next) {
        for (sa = lr->bind_addr; sa; sa = sa->next) {
            if  (sa->port == mc->local_80 
                 && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                mc->can_http = 1;
            }
            else if (sa->port == mc->local_443
                     && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                mc->can_https = 1;
            }
        }
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10037)
                 "server seems%s reachable via http: (port 80->%d) "
                 "and%s reachable via https: (port 443->%d) ",
                 mc->can_http? "" : " not", mc->local_80,
                 mc->can_https? "" : " not", mc->local_443);
    
    /* Complete the properties of the MDs, now that we have the complete, merged
     * server configurations. 
     */
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t*);
        md_merge_srv(md, sc, p);

        /* Check that we have no overlap with the MDs already completed */
        for (j = 0; j < i; ++j) {
            omd = APR_ARRAY_IDX(mc->mds, j, md_t*);
            if ((domain = md_common_name(md, omd)) != NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10038)
                             "two Managed Domains have an overlap in domain '%s'"
                             ", first definition in %s(line %d), second in %s(line %d)",
                             domain, md->defn_name, md->defn_line_number,
                             omd->defn_name, omd->defn_line_number);
                return APR_EINVAL;
            }
        }

        /* Apply to the vhost(s) that this MD matches - if any. Perform some
         * last finishing touches on the MD. */
        if (APR_SUCCESS != (rv = apply_to_servers(md, base_server, p, ptemp))) {
            return rv;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10039)
                     "Completed MD[%s, CA=%s, Proto=%s, Agreement=%s, Drive=%d, renew=%ld]",
                     md->name, md->ca_url, md->ca_proto, md->ca_agreement,
                     md->drive_mode, (long)md->renew_window);
    }
    
    return rv;
}

/**************************************************************************************************/
/* store & registry setup */

static apr_status_t store_file_ev(void *baton, struct md_store_t *store,
                                    md_store_fs_ev_t ev, int group, 
                                    const char *fname, apr_filetype_e ftype,  
                                    apr_pool_t *p)
{
    server_rec *s = baton;
    apr_status_t rv;
    
    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s, "store event=%d on %s %s (group %d)", 
                 ev, (ftype == APR_DIR)? "dir" : "file", fname, group);
                 
    /* Directories in group CHALLENGES and STAGING are written to by our watchdog,
     * running on certain mpms in a child process under a different user. Give them
     * ownership. 
     */
    if (ftype == APR_DIR) {
        switch (group) {
            case MD_SG_CHALLENGES:
            case MD_SG_STAGING:
                rv = md_make_worker_accessible(fname, p);
                if (APR_ENOTIMPL != rv) {
                    return rv;
                }
                break;
            default: 
                break;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t check_group_dir(md_store_t *store, md_store_group_t group, 
                                    apr_pool_t *p, server_rec *s)
{
    const char *dir;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = md_store_get_fname(&dir, store, group, NULL, NULL, p))
        && APR_SUCCESS == (rv = apr_dir_make_recursive(dir, MD_FPROT_D_UALL_GREAD, p))) {
        rv = store_file_ev(s, store, MD_S_FS_EV_CREATED, group, dir, APR_DIR, p);
    }
    return rv;
}

static apr_status_t setup_store(md_mod_conf_t *mc, apr_pool_t *p, server_rec *s,
                                int post_config)
{
    const char *base_dir;
    md_store_t *store;
    apr_status_t rv;
    
    base_dir = ap_server_root_relative(p, mc->base_dir);
    
    if (APR_SUCCESS != (rv = md_store_fs_init(&store, p, base_dir))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10046)"setup store for %s", base_dir);
        goto out;
    }

    if (post_config) {
        md_store_fs_set_event_cb(store, store_file_ev, s);
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_CHALLENGES, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10047) 
                         "setup challenges directory");
            goto out;
        }
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_STAGING, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10048) 
                         "setup staging directory");
            goto out;
        }
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_ACCOUNTS, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10049) 
                         "setup accounts directory");
            goto out;
        }
    }
    
    mc->store = store;
out:
    return rv;
}

static apr_status_t setup_reg(md_reg_t **preg, apr_pool_t *p, server_rec *s, int post_config)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    apr_status_t rv;
    
    sc = md_config_get(s);
    mc = sc->mc;
    
    if (mc->store || APR_SUCCESS == (rv = setup_store(mc, p, s, post_config))) {
        return md_reg_init(preg, p, mc->store);
    }
    return rv;
}

/**************************************************************************************************/
/* logging setup */

static server_rec *log_server;

static int log_is_level(void *baton, apr_pool_t *p, md_log_level_t level)
{
    if (log_server) {
        return APLOG_IS_LEVEL(log_server, level);
    }
    return level <= MD_LOG_INFO;
}

#define LOG_BUF_LEN 16*1024

static void log_print(const char *file, int line, md_log_level_t level, 
                      apr_status_t rv, void *baton, apr_pool_t *p, const char *fmt, va_list ap)
{
    if (log_is_level(baton, p, level)) {
        char buffer[LOG_BUF_LEN];
        
        memset(buffer, 0, sizeof(buffer));
        apr_vsnprintf(buffer, LOG_BUF_LEN-1, fmt, ap);
        buffer[LOG_BUF_LEN-1] = '\0';

        if (log_server) {
            ap_log_error(file, line, APLOG_MODULE_INDEX, level, rv, log_server, "%s",buffer);
        }
        else {
            ap_log_perror(file, line, APLOG_MODULE_INDEX, level, rv, p, "%s", buffer);
        }
    }
}

/**************************************************************************************************/
/* lifecycle */

static apr_status_t cleanup_setups(void *dummy)
{
    (void)dummy;
    log_server = NULL;
    return APR_SUCCESS;
}

static void init_setups(apr_pool_t *p, server_rec *base_server) 
{
    log_server = base_server;
    apr_pool_cleanup_register(p, NULL, cleanup_setups, apr_pool_cleanup_null);
}

/**************************************************************************************************/
/* watchdog based impl. */

#define MD_WATCHDOG_NAME   "_md_"

static APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *wd_get_instance;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *wd_register_callback;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *wd_set_interval;

typedef struct {
    apr_pool_t *p;
    server_rec *s;
    ap_watchdog_t *watchdog;
    int all_valid;
    apr_time_t valid_not_before;
    int error_count;
    int processed_count;

    int error_runs;
    apr_time_t next_change;
    apr_time_t next_valid;
    
    apr_array_header_t *mds;
    md_reg_t *reg;
} md_watchdog;

static apr_status_t drive_md(md_watchdog *wd, md_t *md, apr_pool_t *ptemp)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t renew_time, now, valid_from;
    int errored, renew;
    char ts[APR_RFC822_DATE_LEN];
    
    if (md->state == MD_S_COMPLETE && !md->expires) {
        /* This is our indicator that we did already renewed this managed domain
         * successfully and only wait on the next restart for it to activate */
        now = apr_time_now();
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO(10051) 
                     "md(%s): has been renewed, should be activated in %s", 
                     md->name, (md->valid_from <= now)? "about now" : 
                     md_print_duration(ptemp, md->valid_from - now));
    }
    else if (APR_SUCCESS == (rv = md_reg_assess(wd->reg, md, &errored, &renew, wd->p))) {
        if (errored) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10050) 
                         "md(%s): in error state", md->name);
        }
        else if (renew) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10052) 
                         "md(%s): state=%d, driving", md->name, md->state);
                         
            rv = md_reg_stage(wd->reg, md, NULL, 0, &valid_from, ptemp);
            
            if (APR_SUCCESS == rv) {
                md->state = MD_S_COMPLETE;
                md->expires = 0;
                md->valid_from = valid_from;
                ++wd->processed_count;
                if (!wd->next_valid || wd->next_valid > valid_from) {
                    wd->next_valid = valid_from;
                }
            }
        }
        else {
            apr_rfc822_date(ts, md->expires);
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10053) 
                         "md(%s): is complete, cert expires %s", md->name, ts);
            renew_time = md->expires - md->renew_window;
            if (renew_time < wd->next_change) {
                wd->next_change = renew_time;
            }
        }
    }
    return rv;
}

static apr_status_t run_watchdog(int state, void *baton, apr_pool_t *ptemp)
{
    md_watchdog *wd = baton;
    apr_status_t rv = APR_SUCCESS;
    md_t *md;
    apr_interval_time_t interval, now;
    int i;
    
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10054)
                         "md watchdog start, auto drive %d mds", wd->mds->nelts);
            break;
        case AP_WATCHDOG_STATE_RUNNING:
            assert(wd->reg);
            
            /* normally, we'd like to run at least twice a day */
            interval = apr_time_from_sec(MD_SECS_PER_DAY / 2);

            wd->all_valid = 1;
            wd->valid_not_before = 0;
            wd->processed_count = 0;
            wd->error_count = 0;
            wd->next_change = 0;
            wd->next_valid = 0;
            
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10055)
                         "md watchdog run, auto drive %d mds", wd->mds->nelts);
                         
            /* Check if all Managed Domains are ok or if we have to do something */
            for (i = 0; i < wd->mds->nelts; ++i) {
                md = APR_ARRAY_IDX(wd->mds, i, md_t *);
                
                if (APR_SUCCESS != (rv = drive_md(wd, md, ptemp))) {
                    wd->all_valid = 0;
                    ++wd->error_count;
                    ap_log_error( APLOG_MARK, APLOG_ERR, rv, wd->s, APLOGNO(10056) 
                                 "processing %s", md->name);
                }
            }

            /* Determine when we want to run next */
            wd->error_runs = wd->error_count? (wd->error_runs + 1) : 0;
            if (wd->all_valid) {
                now = apr_time_now();
                if (wd->next_valid > now && (wd->next_valid - now < interval)) {
                    interval = wd->next_valid - now;
                    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, wd->s, 
                                 "Delaying activation of %d Managed Domain%s by %s", 
                                 wd->processed_count, (wd->processed_count > 1)? "s have" : " has",
                                 md_print_duration(ptemp, interval));
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, wd->s, 
                                 "all managed domains are valid");
                }
            }
            else {
                /* back off duration, depending on the errors we encounter in a row */
                interval = apr_time_from_sec(5 << (wd->error_runs - 1));
                if (interval > apr_time_from_sec(60*60)) {
                    interval = apr_time_from_sec(60*60);
                }
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO(10057) 
                             "encountered errors for the %d. time, next run in %d seconds",
                             wd->error_runs, (int)apr_time_sec(interval));
            }
            
            /* We follow the chosen min_interval for re-evaluation, unless we
             * know of a change (renewal) that happens before that. */
            if (wd->next_change) {
                apr_interval_time_t until_next = wd->next_change - apr_time_now();
                if (until_next < interval) {
                    interval = until_next;
                }
            }
            
            /* Set when we'd like to be run next time. 
             * TODO: it seems that this is really only ticking down when the server
             * runs. When you wake up a hibernated machine, the watchdog will not run right away 
             */
            if (APLOGdebug(wd->s)) {
                ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, "next run in %s",
                             md_print_duration(ptemp, interval));
            }
            wd_set_interval(wd->watchdog, interval, wd, run_watchdog);
            break;
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10058)
                         "md watchdog stopping");
            break;
    }

    if (wd->processed_count) {
        now = apr_time_now();
        
        if (wd->all_valid) {
            if (wd->next_valid <= now) {
                rv = md_server_graceful(ptemp, wd->s);
                if (APR_ENOTIMPL == rv) {
                    /* self-graceful restart not supported in this setup */
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO(10059)
                                 "%d Managed Domain%s been setup and changes will be "
                                 "activated on next (graceful) server restart.",
                                 wd->processed_count, (wd->processed_count > 1)? "s have" : " has");
                }
            }
            else {
                /* activation is delayed */
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO(10060)
                         "%d Managed Domain%s been setup, while %d%s "
                         "still being worked on. You may activate the changes made "
                         "by triggering a (graceful) restart at any time.",
                         wd->processed_count, (wd->processed_count > 1)? "s have" : " has",
                         wd->error_count, (wd->error_count > 1)? " are" : " is");
        }
    }
    
    return APR_SUCCESS;
}

static apr_status_t start_watchdog(apr_array_header_t *names, apr_pool_t *p, 
                                   md_reg_t *reg, server_rec *s)
{
    apr_allocator_t *allocator;
    md_watchdog *wd;
    apr_pool_t *wdp;
    apr_status_t rv;
    const char *name;
    md_t *md;
    int i, errored, renew;
    
    wd_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    wd_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    wd_set_interval = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_set_callback_interval);
    
    if (!wd_get_instance || !wd_register_callback || !wd_set_interval) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10061) "mod_watchdog is required");
        return !OK;
    }
    
    /* We want our own pool with own allocator to keep data across watchdog invocations */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    rv = apr_pool_create_ex(&wdp, p, NULL, allocator);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10062) "md_watchdog: create pool");
        return rv;
    }
    apr_allocator_owner_set(allocator, wdp);
    apr_pool_tag(wdp, "md_watchdog");

    wd = apr_pcalloc(wdp, sizeof(*wd));
    wd->p = wdp;
    wd->reg = reg;
    wd->s = s;
    
    wd->mds = apr_array_make(wd->p, 10, sizeof(md_t *));
    for (i = 0; i < names->nelts; ++i) {
        name = APR_ARRAY_IDX(names, i, const char *);
        md = md_reg_get(wd->reg, name, wd->p);
        if (md) {
            md_reg_assess(wd->reg, md, &errored, &renew, wd->p);
            if (errored) {
                ap_log_error( APLOG_MARK, APLOG_WARNING, 0, wd->s, APLOGNO(10063) 
                             "md(%s): seems errored. Will not process this any further.", name);
            }
            else {
                ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10064) 
                             "md(%s): state=%d, driving", name, md->state);
                APR_ARRAY_PUSH(wd->mds, md_t*) = md;
            }
        }
    }

    if (!wd->mds->nelts) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10065)
                     "no managed domain in state to drive, no watchdog needed, "
                     "will check again on next server restart");
        apr_pool_destroy(wd->p);
        return APR_SUCCESS;
    }
    
    if (APR_SUCCESS != (rv = wd_get_instance(&wd->watchdog, MD_WATCHDOG_NAME, 0, 1, wd->p))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(10066) 
                     "create md watchdog(%s)", MD_WATCHDOG_NAME);
        return rv;
    }
    rv = wd_register_callback(wd->watchdog, 0, wd, run_watchdog);
    ap_log_error(APLOG_MARK, rv? APLOG_CRIT : APLOG_DEBUG, rv, s, APLOGNO(10067) 
                 "register md watchdog(%s)", MD_WATCHDOG_NAME);
    return rv;
}
 
static void load_stage_sets(apr_array_header_t *names, apr_pool_t *p, 
                            md_reg_t *reg, server_rec *s)
{
    const char *name; 
    apr_status_t rv;
    int i;
    
    for (i = 0; i < names->nelts; ++i) {
        name = APR_ARRAY_IDX(names, i, const char*);
        if (APR_SUCCESS == (rv = md_reg_load(reg, name, p))) {
            ap_log_error( APLOG_MARK, APLOG_INFO, rv, s, APLOGNO(10068) 
                         "%s: staged set activated", name);
        }
        else if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_error( APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10069)
                         "%s: error loading staged set", name);
        }
    }
    return;
}

static apr_status_t md_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    const char *mod_md_init_key = "mod_md_init_counter";
    void *data = NULL;
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    apr_array_header_t *drive_names;
    md_reg_t *reg;
    apr_status_t rv = APR_SUCCESS;
    const md_t *md;
    int i;
    
    apr_pool_userdata_get(&data, mod_md_init_key, s->process->pool);
    if (data == NULL) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10070)
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_md_init_key,
                              apr_pool_cleanup_null, s->process->pool);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(10071)
                     "mod_md (v%s), initializing...", MOD_MD_VERSION);
    }

    init_setups(p, s);
    
    md_log_set(log_is_level, log_print, NULL);

    sc = md_config_get(s);
    mc = sc->mc;
    
    /* 1. Check uniqueness of MDs, calculate global, configured MD list.
     * If successful, we have a list of MD definitions that do not overlap. */
    /* We also need to find out if we can be reached on 80/443 from the outside (e.g. the CA) */
    if (APR_SUCCESS != (rv = md_calc_md_list(p, plog, ptemp, s))) {
        goto out;
    }
    
    /* 2. Synchronize the defintions we now have with the store via a registry (reg). */
    if (APR_SUCCESS != (rv = setup_reg(&reg, p, s, 1))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10072)
                     "setup md registry");
        goto out;
    }
    if (APR_SUCCESS != (rv = md_reg_sync(reg, p, ptemp, mc->mds, 
                                         mc->can_http, mc->can_https))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10073)
                     "synching %d mds to registry", mc->mds->nelts);
        goto out;
    }
    
    /* 3. Determine the managed domains that are in auto drive_mode. For those,
     * determine in which state they are:
     *  - UNKNOWN:            should not happen, report, dont drive
     *  - ERROR:              something we do not know how to fix, report, dont drive
     *  - INCOMPLETE/EXPIRED: need to drive them right away
     *  - COMPLETE:           determine when cert expires, drive when the time comes
     *
     * Start the watchdog if we have anything, now or in the future.
     */
    drive_names = apr_array_make(ptemp, mc->mds->nelts+1, sizeof(const char *));
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, const md_t *);
        switch (md->drive_mode) {
            case MD_DRIVE_AUTO:
                if (md_array_str_index(mc->unused_names, md->name, 0, 0) >= 0) {
                    break;
                }
                /* fall through */
            case MD_DRIVE_ALWAYS:
                APR_ARRAY_PUSH(drive_names, const char *) = md->name; 
                break;
            default:
                /* leave out */
                break;
        }
    }
    
    /* 4. I there are MDs to drive, start a watchdog to check on them regularly */
    if (drive_names->nelts > 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10074)
                     "%d out of %d mds are configured for auto-drive", 
                     drive_names->nelts, mc->mds->nelts);
    
        load_stage_sets(drive_names, p, reg, s);
        md_http_use_implementation(md_curl_get_impl(p));
        rv = start_watchdog(drive_names, p, reg, s);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10075)
                     "no mds to auto drive, no watchdog needed");
    }
out:     
    return rv;
}

/**************************************************************************************************/
/* Access API to other httpd components */

static int md_is_managed(server_rec *s)
{
    md_srv_conf_t *conf = md_config_get(s);

    if (conf && conf->assigned) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10076) 
                     "%s: manages server %s", conf->assigned->name, s->server_hostname);
        return 1;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,  
                 "server %s is not managed", s->server_hostname);
    return 0;
}

static apr_status_t md_get_credentials(server_rec *s, apr_pool_t *p,
                                       const char **pkeyfile, const char **pcertfile,
                                       const char **pchainfile)
{
    apr_status_t rv = APR_ENOENT;    
    md_srv_conf_t *sc;
    md_reg_t *reg;
    const md_t *md;
    
    *pkeyfile = NULL;
    *pcertfile = NULL;
    *pchainfile = NULL;
    
    sc = md_config_get(s);
    
    if (sc && sc->assigned) {
        assert(sc->mc);
        assert(sc->mc->store);
        if (APR_SUCCESS == (rv = md_reg_init(&reg, p, sc->mc->store))) {
            md = md_reg_get(reg, sc->assigned->name, p);
            if (md->state != MD_S_COMPLETE) {
                return APR_EAGAIN;
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10077) 
                         "%s: loading credentials for server %s", md->name, s->server_hostname);
            return md_reg_get_cred_files(reg, md, p, pkeyfile, pcertfile, pchainfile);
        }
    }
    return rv;
}


static int md_is_challenge(conn_rec *c, const char *servername,
                           X509 **pcert, EVP_PKEY **pkey)
{
    md_srv_conf_t *sc;
    apr_size_t slen, sufflen = sizeof(MD_TLSSNI01_DNS_SUFFIX) - 1;
    apr_status_t rv;

    slen = strlen(servername);
    if (slen <= sufflen 
        || apr_strnatcasecmp(MD_TLSSNI01_DNS_SUFFIX, servername + slen - sufflen)) {
        return 0;
    }
    
    sc = md_config_get(c->base_server);
    if (sc && sc->mc->store) {
        md_store_t *store = sc->mc->store;
        md_cert_t *mdcert;
        md_pkey_t *mdpkey;
        
        rv = md_store_load(store, MD_SG_CHALLENGES, servername, 
                           MD_FN_TLSSNI01_CERT, MD_SV_CERT, (void**)&mdcert, c->pool);
        if (APR_SUCCESS == rv && (*pcert = md_cert_get_X509(mdcert))) {
            rv = md_store_load(store, MD_SG_CHALLENGES, servername, 
                               MD_FN_TLSSNI01_PKEY, MD_SV_PKEY, (void**)&mdpkey, c->pool);
            if (APR_SUCCESS == rv && (*pkey = md_pkey_get_EVP_PKEY(mdpkey))) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(10078)
                              "%s: is a tls-sni-01 challenge host", servername);
                return 1;
            }
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, rv, c, APLOGNO(10079)
                          "%s: challenge data not complete, key unavailable", servername);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO(10080)
                          "%s: unknown TLS SNI challenge host", servername);
        }
    }
    *pcert = NULL;
    *pkey = NULL;
    return 0;
}

/**************************************************************************************************/
/* ACME challenge responses */

#define ACME_CHALLENGE_PREFIX       "/.well-known/acme-challenge/"

static int md_http_challenge_pr(request_rec *r)
{
    apr_bucket_brigade *bb;
    const md_srv_conf_t *sc;
    const char *name, *data;
    apr_status_t rv;
            
    if (!strncmp(ACME_CHALLENGE_PREFIX, r->parsed_uri.path, sizeof(ACME_CHALLENGE_PREFIX)-1)) {
        if (r->method_number == M_GET) {
            md_store_t *store;
        
            sc = ap_get_module_config(r->server->module_config, &md_module);
            store = sc? sc->mc->store : NULL;
            
            name = r->parsed_uri.path + sizeof(ACME_CHALLENGE_PREFIX)-1;

            r->status = HTTP_NOT_FOUND;
            if (!ap_strchr_c(name, '/') && store) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                              "Challenge for %s (%s)", r->hostname, r->uri);

                rv = md_store_load(store, MD_SG_CHALLENGES, r->hostname, 
                                   MD_FN_HTTP01, MD_SV_TEXT, (void**)&data, r->pool);
                if (APR_SUCCESS == rv) {
                    apr_size_t len = strlen(data);
                    
                    r->status = HTTP_OK;
                    apr_table_setn(r->headers_out, "Content-Length", apr_ltoa(r->pool, (long)len));
                    
                    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
                    apr_brigade_write(bb, NULL, NULL, data, len);
                    ap_pass_brigade(r->output_filters, bb);
                    apr_brigade_cleanup(bb);
                }
                else if (APR_STATUS_IS_ENOENT(rv)) {
                    return HTTP_NOT_FOUND;
                }
                else if (APR_ENOENT != rv) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10081)
                                  "loading challenge %s from store", name);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            return r->status;
        }
        else {
            return HTTP_NOT_IMPLEMENTED;
        }
    }
    return DECLINED;
}

/* Runs once per created child process. Perform any process 
 * related initionalization here.
 */
static void md_child_init(apr_pool_t *pool, server_rec *s)
{
}

/* Install this module into the apache2 infrastructure.
 */
static void md_hooks(apr_pool_t *pool)
{
    static const char *const mod_ssl[] = { "mod_ssl.c", NULL};

    md_acme_init(pool, AP_SERVER_BASEVERSION);
        
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");
    
    /* Run once after configuration is set, before mod_ssl.
     */
    ap_hook_post_config(md_post_config, NULL, mod_ssl, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(md_child_init, NULL, mod_ssl, APR_HOOK_MIDDLE);

    /* answer challenges *very* early, before any configured authentication may strike */
    ap_hook_post_read_request(md_http_challenge_pr, NULL, NULL, APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(md_is_managed);
    APR_REGISTER_OPTIONAL_FN(md_get_credentials);
    APR_REGISTER_OPTIONAL_FN(md_is_challenge);
}
