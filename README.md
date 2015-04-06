# nginx

ngx源码剖析
李文强所有，未经本人同意禁止复制拷贝

```
nginx.conf

#user  nobody;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}
    }


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}


    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

}



```

## ngx_strerror_init

ngx_errno.c
缓存系统信息
perror errno

## ngx_get_options

解析命令行参数

## ngx_time_init

## ngx_regex_init

## ngx_log_init

ngx_log.c
初始化日志结构体

```



```

## ngx_ssl_init

ngx_event_openssl.c
初始化ssl库


## ngx_save_argv

保存命令行参数到程序的堆内存

```
ngx_argv = ngx_alloc((argc + 1) * sizeof(char *), cycle->log);
ngx_cpystrn((u_char *) ngx_argv[i], (u_char *) argv[i], len);

```

## ngx_process_options

设置工作路径
配置文件路径
默认路径等。


## ngx_os_init

初始化系统参数
获取内存页大小
CPU核数
socket句柄最大数
初始化随机数种子


## ngx_crc32_table_init

## ngx_add_inherited_sockets

平滑升级
获取环变量中的socket bind的文件描述符
获取bind的地址和端口
结果放到cycle->listening

## ngx_init_cycle

ngx_cycle.c 文件

```
cycle->conf_ctx = ngx_pcalloc(pool, ngx_max_module * sizeof(void *));


```

### ngx_timezone_update

#### 分支主题

### ngx_time_update

### ngx_create_pool

### create_conf

为核心配置项分配内存

```
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_conf) {
            rv = module->create_conf(cycle);
            if (rv == NULL) {
                ngx_destroy_pool(pool);
                return NULL;
            }
            cycle->conf_ctx[ngx_modules[i]->index] = rv;
        }
    }
```

#### ngx_core_module_ctx

nginx.c文件
ngx_core_conf_t  ngx_core_module_create_conf(ngx_cycle_t *cycle)

#### ngx_openssl_module_ctx

event/ngx_event_openssl.c
ngx_openssl_conf_t ngx_openssl_create_conf(ngx_cycle_t *cycle)

#### ngx_events_module_ctx

event/ngx_event.c
NULL

#### ngx_http_module_ctx

http/ngx_http.c
NULL

### ngx_conf_param

解析命令行参数的配置项 
 
 ```
    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    conf.pool = pool;
    conf.log = log;
    conf.module_type = NGX_CORE_MODULE;
    conf.cmd_type = NGX_MAIN_CONF;
```

### ngx_conf_parse

解析配置文件，核心模块的MAIN配置项

core/ngx_conf_file.c 文件
```
char *
ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename)
```

#### ngx_conf_read_token

#### ngx_conf_handler

```
if (ngx_modules[i]->type != NGX_CONF_MODULE
                && ngx_modules[i]->type != cf->module_type)
            {
                continue;
            }
            
            if (cmd->type & NGX_DIRECT_CONF) {
                conf = ((void **) cf->ctx)[ngx_modules[i]->index];

            } else if (cmd->type & NGX_MAIN_CONF) {
                conf = &(((void **) cf->ctx)[ngx_modules[i]->index]);

            } else if (cf->ctx) {
                confp = *(void **) ((char *) cf->ctx + cmd->conf);

                if (confp) {
                    conf = confp[ngx_modules[i]->ctx_index];
                }
            }
            
cmd->set(cf, cmd, conf);
```

##### ngx_core_commands

core/nginx.c 文件
ngx_core_conf_t 设置结构体
daemon：ngx_conf_set_flag_slot










```
typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes;
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;
     ngx_int_t                rlimit_sigpending;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     uint64_t                *cpu_affinity;

     char                    *username;
     ngx_uid_t                user;
     ngx_gid_t                group;

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;

#if (NGX_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;
```

##### ngx_events_commands

event/ngx_event.c 文件
events： ngx_events_block

###### ngx_events_block

```
ngx_modules[i]->ctx_index = ngx_event_max_module++;

    ctx = ngx_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *ctx = ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(void **) conf = ctx;
    
```


####### create_conf

```
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = ngx_modules[i]->ctx;

        if (m->create_conf) {
            (*ctx)[ngx_modules[i]->ctx_index] = m->create_conf(cf->cycle);
            if ((*ctx)[ngx_modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }
```

######## ngx_event_core_module_ctx

event/ngx_event.c 文件

```
static void *
ngx_event_core_create_conf(ngx_cycle_t *cycle)
return ngx_event_conf_t；




```


event/ngx_event.h
```


    ngx_flag_t    multi_accept;
    ngx_flag_t    accept_mutex;

    ngx_msec_t    accept_mutex_delay;

    u_char       *name;

#if (NGX_DEBUG)
    ngx_array_t   debug_connection;
#endif
} ngx_event_conf_t;
```

######## ngx_epoll_module_ctx

event/modules/ngx_epoll_module.c文件

```
static void *
ngx_epoll_create_conf(ngx_cycle_t *cycle)

    return ngx_epoll_conf_t 



typedef struct {
    ngx_uint_t  events;
    ngx_uint_t  aio_requests;
} ngx_epoll_conf_t;


```




####### ngx_conf_parse

```
    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;

    rv = ngx_conf_parse(cf, NULL);
```

######## ngx_event_core_commands

event/ngx_event.c 文件

```
worker_connections：ngx_event_connections
connections：ngx_event_connections
use：ngx_event_use

```


######### ngx_event_connections

event/ngx_event.c

```

ngx_event_conf_t.connections
cf->cycle->connection_n


```

######### ngx_event_use

event/ngx_event.c

```
for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }
    ecf->use = ngx_modules[m]->ctx_index;
    ecf->name = module->name->data;
｝
```


######## ngx_epoll_commands

event/modules/ngx_epoll_module.c文件

```
epoll_events
worker_aio_requests

```



####### init_conf

```
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = ngx_modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle, (*ctx)[ngx_modules[i]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }
```


######## ngx_event_core_module_ctx



```
static char *
ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf)
{
    fd = epoll_create(100);
    module = &ngx_devpoll_module;
｝


```

######## ngx_epoll_module_ctx



```
static char *
ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    return NGX_CONF_OK;
｝

```

##### ngx_openssl_commands

event/ngx_event_openssl.c 文件

```
ssl_engine： ngx_openssl_engine

ngx_openssl_conf_t 结构体
typedef struct {
    ngx_uint_t  engine;   /* unsigned  engine:1; */
} ngx_openssl_conf_t;

```

###### ngx_openssl_engine




```
static char *
ngx_openssl_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ENGINE_by_id
  ENGINE_set_default
  ENGINE_free
｝

```

##### ngx_http_commands

http/ngx_http.c 文件
```
http: ngx_http_block




```
http/ngx_http_config.h

```
typedef struct {
    void        **main_conf;
    void        **srv_conf;
    void        **loc_conf;
} ngx_http_conf_ctx_t;

```


###### ngx_http_block

ngx_http.c


```

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));


```

####### ngx_http_conf_ctx_t

ngx_http.c


```
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_http_conf_ctx_t **) conf = ctx;
    
    
        ngx_http_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_http_max_module++;
    }
    
        ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_http_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
        for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }
    
```

######## create_main_conf

######### ngx_http_core_module_ctx

ngx_http_core_module.c

```

static void *
ngx_http_core_create_main_conf(ngx_conf_t *cf)
{



｝

```

ngx_http_core_module.h

```

typedef struct {
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;

    ngx_hash_t                 variables_hash;

    ngx_array_t                variables;       /* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;

    ngx_uint_t                 server_names_hash_max_size;
    ngx_uint_t                 server_names_hash_bucket_size;

    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    ngx_hash_keys_arrays_t    *variables_keys;

    ngx_array_t               *ports;

    ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;

```

######### ngx_http_upstream_module_ctx

ngx_http_upstream.c

```

static void *
ngx_http_upstream_create_main_conf(ngx_conf_t *cf)
{



｝

```


ngx_http_upstream.h

```
typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;
```

######## create_srv_conf

######### ngx_http_core_module_ctx



```
static void *
ngx_http_core_create_srv_conf(ngx_conf_t *cf)
{
｝
```
ngx_http_core_module.h
```
typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    ngx_http_conf_ctx_t        *ctx;

    ngx_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;
```

######### ngx_http_ssl_module_ctx

ngx_http_ssl_module.c


```
static void *
ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
{
｝

```

ngx_http_ssl_module.h
```
typedef struct {
    ngx_flag_t                      enable;

    ngx_ssl_t                       ssl;

    ngx_flag_t                      prefer_server_ciphers;

    ngx_uint_t                      protocols;

    ngx_uint_t                      verify;
    ngx_uint_t                      verify_depth;

    size_t                          buffer_size;

    ssize_t                         builtin_session_cache;

    time_t                          session_timeout;

    ngx_str_t                       certificate;
    ngx_str_t                       certificate_key;
    ngx_str_t                       dhparam;
    ngx_str_t                       ecdh_curve;
    ngx_str_t                       client_certificate;
    ngx_str_t                       trusted_certificate;
    ngx_str_t                       crl;

    ngx_str_t                       ciphers;

    ngx_array_t                    *passwords;

    ngx_shm_zone_t                 *shm_zone;

    ngx_flag_t                      session_tickets;
    ngx_array_t                    *session_ticket_keys;

    ngx_flag_t                      stapling;
    ngx_flag_t                      stapling_verify;
    ngx_str_t                       stapling_file;
    ngx_str_t                       stapling_responder;

    u_char                         *file;
    ngx_uint_t                      line;
} ngx_http_ssl_srv_conf_t;

```

######## create_loc_conf

######### ngx_http_core_module_ctx


```
static void *
ngx_http_core_create_loc_conf(ngx_conf_t *cf)
{
｝

```


```

struct ngx_http_core_loc_conf_s {
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
#if (NGX_HTTP_DEGRADATION)
    unsigned      gzip_disable_degradation:2;
#endif
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
#if (NGX_HAVE_FILE_AIO)
    ngx_flag_t    aio;                     /* aio */
#endif
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_flag_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    ngx_array_t  *error_pages;             /* error_page */
    ngx_http_try_file_t    *try_files;     /* try_files */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};

```

####### preconfiguration

######## ngx_http_core_module_ctx


```
static ngx_int_t
ngx_http_core_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_variables_add_core_vars(cf);
}

```

######## ngx_http_ssl_module_ctx

ngx_http_ssl_module.c

```
static ngx_http_variable_t  ngx_http_ssl_vars[]

static ngx_int_t
ngx_http_ssl_add_variables(ngx_conf_t *cf)
{
｝
```

####### ngx_conf_parse



```
    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
```

######## ngx_http_core_commands

ngx_http_core_module.c

```
server： ngx_http_core_server
location： ngx_http_core_location
listen： ngx_http_core_listen
server_name： ngx_http_core_server_name

```

######### ngx_http_core_server

ngx_http_core_module.c

```
cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];

    //多个虚拟主机配置结构体
    cscfp = ngx_array_push(&cmcf->servers);
    *cscfp = cscf;
    
//设置默认端口
if (rv == NGX_CONF_OK && !cscf->listen) {
        ngx_memzero(&lsopt, sizeof(ngx_http_listen_opt_t));

        sin = &lsopt.u.sockaddr_in;

        sin->sin_family = AF_INET;
#if (NGX_WIN32)
        sin->sin_port = htons(80);
#else
        sin->sin_port = htons((getuid() == 0) ? 80 : 8000);
#endif
        sin->sin_addr.s_addr = INADDR_ANY;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.backlog = NGX_LISTEN_BACKLOG;
        lsopt.rcvbuf = -1;
        lsopt.sndbuf = -1;
#if (NGX_HAVE_SETFIB)
        lsopt.setfib = -1;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
        lsopt.fastopen = -1;
#endif
        lsopt.wildcard = 1;

        (void) ngx_sock_ntop(&lsopt.u.sockaddr, lsopt.socklen, lsopt.addr,
                             NGX_SOCKADDR_STRLEN, 1);

        if (ngx_http_add_listen(cf, cscf, &lsopt) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

```

########## ngx_http_conf_ctx_t

ngx_http_core_module.c


```
create_srv_conf
create_loc_conf

```

########## ngx_conf_parse



```
    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_SRV_CONF;
```

以nginx.conf配置文件的HTTPS server为例解析
```
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

```

########### ngx_http_core_commands

ngx_http_core_module.c
```
listen： ngx_http_core_listen
server_name： ngx_http_core_server_name

location：ngx_http_core_location



```

############ ngx_http_core_listen

ngx_http_core_module.c

```
static char *
ngx_http_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *cscf = conf;
    ngx_http_listen_opt_t   lsopt;
    ngx_http_add_listen(cf, cscf, &lsopt);

}

```

ngx_http_core_module.h


```

typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HTTP_SPDY)
    unsigned                   spdy:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:1;
#endif
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_http_listen_opt_t;

```

############# ngx_http_add_listen

ngx_http.c

```
ngx_int_t
ngx_http_add_listen(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_listen_opt_t *lsopt)
{
   cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
   
   cmcf->ports = ngx_array_create(cf->temp_pool, 2,
                                       sizeof(ngx_http_conf_port_t));

    port = ngx_array_push(cmcf->ports);

｝

    return ngx_http_add_address(cf, cscf, port, lsopt);

```


############## ngx_http_add_addresses

############## ngx_http_add_address

############### ngx_http_add_server

############ ngx_http_core_server_name



```
static char *
ngx_http_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *cscf = conf;
    ngx_http_server_name_t  *sn = ngx_array_push(&cscf->server_names);
｝

```
ngx_http_core_module.h
```
typedef struct {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
} ngx_http_server_name_t;

```

############ ngx_http_core_location



```
static char *
ngx_http_core_location(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));


    ngx_http_add_location(cf, &pclcf->locations, clcf);


    rv = ngx_conf_parse(cf, NULL);
    
｝


```


############# ngx_http_conf_ctx_t

############## create_loc_conf




```

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[ngx_modules[i]->ctx_index] =
                                                   module->create_loc_conf(cf);
            if (ctx->loc_conf[ngx_modules[i]->ctx_index] == NULL) {
                 return NGX_CONF_ERROR;
            }
        }
    }


```

############# ngx_http_add_location

ngx_http.c


```
ngx_int_t
ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
    ngx_http_core_loc_conf_t *clcf)
{


｝

```


############# ngx_conf_parse




```
    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;

```

########### ngx_http_ssl_commands

http/modules/ngx_http_ssl_module.c

```
ssl_certificate： 
ssl_certificate_key：

```

########## ngx_http_add_listen

######## 分支主题

####### init_main_conf

######## ngx_http_core_module_ctx



```
static char *
ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
   ngx_http_core_main_conf_t *cmcf = conf;
｝


```

######## 分支主题

####### ngx_http_merge_servers

ngx_http.c

```


```


######## merge_srv_conf

######## merge_loc_conf

######## ngx_http_merge_locations

####### ngx_http_init_locations

####### ngx_http_init_static_location_trees

####### ngx_http_init_phases

####### ngx_http_init_headers_in_hash

####### postconfiguration

####### ngx_http_variables_init_vars

####### ngx_http_init_phase_handlers

ngx_http,c

```
static ngx_int_t
ngx_http_init_phase_handlers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{

}

```

####### ngx_http_optimize_servers

ngx_http.c
```
static ngx_int_t
ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_array_t *ports)
{

｝

```

######## ngx_http_server_names

ngx_http.c
hash虚拟主机
```
static ngx_int_t
ngx_http_server_names(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_conf_addr_t *addr)
{

｝

```


```
ngx_http_conf_addr_t ｛
  ngx_hash_t hash;
  ngx_hash_wildcard_t *wc_head;
  ngx_hash_wildcard_t *wc_tail;
｝
```

######## ngx_http_init_listening

ngx_http.c
初始化cycle->listening
```
static ngx_int_t
ngx_http_init_listening(ngx_conf_t *cf, ngx_http_conf_port_t *port)
{
    ls = ngx_http_add_listening(cf, &addr[i]);
    hport = ngx_pcalloc(cf->pool, sizeof(ngx_http_port_t));
    ls->servers = hport;
    hport->naddrs = 1;
    ngx_http_add_addrs(cf, hport, addr)
｝
```


######### ngx_http_add_listening

ngx_http.c


```
static ngx_listening_t *
ngx_http_add_listening(ngx_conf_t *cf, ngx_http_conf_addr_t *addr)
{

    ls->handler = ngx_http_init_connection;

｝


```

########## ngx_create_listening

ngx_connection.c

```
ngx_listening_t *
ngx_create_listening(ngx_conf_t *cf, void *sockaddr, socklen_t socklen)
{
    ls = ngx_array_push(&cf->cycle->listening);
    
｝


```
ngx_connection.h
```
struct ngx_listening_s {
    ngx_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    ngx_str_t           addr_text;

    int                 type;

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;

    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;
    ngx_connection_t   *connection;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};
```

######### ngx_http_add_addrs

ngx_http.c
虚拟主机赋值
```
static ngx_int_t
ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{

｝
```

### init_conf

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->init_conf) {
            if (module->init_conf(cycle, cycle->conf_ctx[ngx_modules[i]->index])
                == NGX_CONF_ERROR)
            {
                environ = senv;
                ngx_destroy_cycle_pools(&conf);
                return NULL;
            }
        }
    }

#### ngx_core_module_ctx

nginx.c

```
static char *
ngx_core_module_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_core_conf_t  *ccf = conf;
｝

```

#### ngx_openssl_module_ctx

NULL

#### ngx_events_module_ctx


```
static char *
ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
{
｝
```

#### ngx_http_module_ctx

NULL

### ngx_create_paths

ngx_file.c

创建目录，并修改所属和权限
mkdir chmod chown


### ngx_log_open_default

### ngx_open_file

### ngx_open_listening_sockets

ngx_connection.c
处理cycle->listening

```
ngx_int_t
ngx_open_listening_sockets(ngx_cycle_t *cycle)
{
    s = ngx_socket(ls[i].sockaddr->sa_family, ls[i].type, 0);
    
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int));
                           
    ngx_nonblocking(s);
    bind(s, ls[i].sockaddr, ls[i].socklen);
    listen(s, ls[i].backlog);
    
    ls[i].listen = 1;
    ls[i].fd = s;
｝

```


### init_module

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_module) {
            if (ngx_modules[i]->init_module(cycle) != NGX_OK) {
                /* fatal */
                exit(1);
            }
        }
    }

#### ngx_event_core_module

ngx_event.c

```
static ngx_int_t
ngx_event_module_init(ngx_cycle_t *cycle)
{
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_timer_resolution = ccf->timer_resolution;

}
```

## ngx_create_pidfile

## ngx_log_redirect_stderr

## ngx_master_process_cycle

## ngx_single_process_cycle

os/unix/ngx_process_cycle.c

```

ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }
    
    for(;;) {
    ngx_process_events_and_timers(cycle);
    }
    
    
｝


```


### init_process

#### ngx_event_core_module

ngx_event.c
为每个listening结构分配connection结构
```
static ngx_int_t
ngx_event_process_init(ngx_cycle_t *cycle)
{
    ngx_use_accept_mutex = 0;
    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_events);
    
    ngx_event_timer_init(cycle->log);
    
    //查找use配置使用的模块
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (ngx_modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        module->actions.init(cycle, ngx_timer_resolution);
        break;
    }

    //设置定时器
    
    
    //
    cycle->files_n
    cycle->files
    cycle->connections =
    cycle->read_events =
    cycle->write_events =
    
    
    cycle->free_connections = 
    
    //为监听结构体分配connection结构体
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ngx_get_connection(ls[i].fd, cycle->log);
        c->listening = &ls[i];
        ls[i].connection = c;
        rev = c->read;
        rev->accept = 1;
        
        //accept回调函数
        rev->handler = ngx_event_accept;
        //监听时间是在这里被加入到epool管理的
        ngx_add_event(rev, NGX_READ_EVENT, 0);
        
    ｝
    
}

```


##### ngx_event_timer_init

##### actions.init

ngx_epoll_module.c

```
ngx_epoll_module_ctx
static ngx_int_t
ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    epoll_create(cycle->connection_n / 2);
    event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
    nevents = epcf->events;
    
    //为全局变量赋值，实现了类似多态
    ngx_event_actions = ngx_epoll_module_ctx.actions;
}


```

##### ngx_get_connection

ngx_connection.c

```
ngx_connection_t *
ngx_get_connection(ngx_socket_t s, ngx_log_t *log)
{
    c = ngx_cycle->free_connections;
    ngx_cycle->free_connections = c->data;

}
```

##### ngx_add_event

event/ngx_event.h
```
//ngx_event_actions 在actions.init中赋值
#define ngx_add_event        ngx_event_actions.add
```

###### ngx_epoll_add_event

ngx_epoll_module.c

```

ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

epoll_ctl();


ev->active = 1;

```

### ngx_process_events_and_timers

ngx_event.c

```
void
ngx_process_events_and_timers(ngx_cycle_t *cycle)
{
    timer = ngx_event_find_timer(
    flags = NGX_UPDATE_TIME;
    flags |= NGX_POST_EVENTS;
    ngx_trylock_accept_mutex(cycle) ;
    //.......
    (void) ngx_process_events(cycle, timer, flags);
    ngx_event_process_posted(cycle, &ngx_posted_accept_events);
    ngx_shmtx_unlock(&ngx_accept_mutex);
    ngx_event_process_posted(cycle, &ngx_posted_events);
｝

```


#### ngx_process_events

event/ngx_event.h
```
#define ngx_process_events   ngx_event_actions.process_events
```

event/modules/ngx_epoll_module.c
```
ngx_event_actions = ngx_epoll_module_ctx.actions;
```

##### ngx_epoll_process_events

ngx_epoll_module.c

```
static ngx_int_t
ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    events = epoll_wait(ep, event_list, (int) nevents, timer);
    
    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;
        rev->ready = 1;
        
        rev->handler(rev);
    
    }
｝
```


###### rev->handler

1.  `ngx_http.c` 文件 `ngx_event_process_init` 函数中赋值` ngx_event_accept `

####### ngx_event_accept

event/ngx_event_accept.c
`accept`链接`ngx_get_connection`一个`ngx_connection_t`
```
void
ngx_event_accept(ngx_event_t *ev)
{
    s = accept(lc->fd, (struct sockaddr *) sa, &socklen);
    
    //从cycle->free_connect 取一个链接
    c = ngx_get_connection(s, ev->log);
    c->pool = ngx_create_pool(ls->pool_size, ev->log);
    
    c->recv = ngx_recv;
    c->send = ngx_send;
    c->listening = ls;
    
    rev = c->read;
    wev = c->write;
    
    ls->handler(c);
    
}

```

######## ls->handler


1. `ngx_http.c` 文件中`ngx_http_add_listening`函数中赋值`ls->handler = ngx_http_init_connection;`

######### ngx_http_init_connection

http/ngx_http_request.c

```
void
ngx_http_init_connection(ngx_connection_t *c)
{
    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    c->data = hc;
    
    
    hc->addr_conf = &addr[0].conf;
    hc->conf_ctx = hc->addr_conf->default_server->ctx;
    
    rev = c->read;
    rev->handler = ngx_http_wait_request_handler;
    c->write->handler = ngx_http_empty_handler;
    
    #SSL
    hc->ssl = 1;
    rev->handler = ngx_http_ssl_handshake;
    ##
    
    rev->handler(rev);
    
    //ngx_add_timer(rev, c->listening->post_accept_timeout);
    //ngx_reusable_connection(c, 1);

    //ngx_handle_read_event(rev, 0);
    
}

```

########## ngx_http_ssl_handshake

ngx_http_request.c

```
static void
ngx_http_ssl_handshake(ngx_event_t *rev)
{

}

```

########### ngx_ssl_create_connection

ngx_event_openssl.c

```
ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
{
    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    sc->connection = SSL_new(ssl->ctx);
    SSL_set_fd(sc->connection, c->fd)
    SSL_set_ex_data(sc->connection, ngx_ssl_connection_index, c)
    c->ssl = sc;
｝
```

########### ngx_ssl_handshake

########### ngx_http_ssl_handshake_handler

########## ngx_http_wait_request_handler

ngx_http_request.c

```
static void
ngx_http_wait_request_handler(ngx_event_t *rev)
{
    n = c->recv(c, b->last, size);
    b->last += n;
    c->data = ngx_http_create_request(c);
    rev->handler = ngx_http_process_request_line;
    ngx_http_process_request_line(rev);
｝
```
此时的recv函数指针：
os/unix/ngx_recv.c
```
ssize_t
ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
}
```


########### ngx_http_create_request

########### ngx_http_process_request_line

ngx_http_request.c

```
static void
ngx_http_process_request_line(ngx_event_t *rev)
{


}

```

############ ngx_http_read_request_header


```
static ssize_t
ngx_http_read_request_header(ngx_http_request_t *r)
{
}
```

############ ngx_http_parse_request_line

http/ngx_http_parse.c
```
ngx_int_t
ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b)
{
}
```

############ ngx_http_process_request_uri

ngx_http_request.c

```
ngx_int_t
ngx_http_process_request_uri(ngx_http_request_t *r)
{

｝

```

############ ngx_http_validate_host

############ ngx_http_set_virtual_server

############ ngx_http_process_request_headers

############# ngx_http_read_request_header

############# ngx_http_parse_header_line

############# ngx_http_process_request_header

############# ngx_http_process_request

ngx_http_request.c


```
    c->read->handler = ngx_http_request_handler;
    c->write->handler = ngx_http_request_handler;
    r->read_event_handler = ngx_http_block_reading;

```


############## ngx_http_handler

ngx_http_core_module.c


############### ngx_http_core_run_phases

############## ngx_http_run_posted_requests

#### ngx_event_process_posted
