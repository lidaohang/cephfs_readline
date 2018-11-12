/* Author: lihanglucien <lihang_net@126.com>
 *
 * File: ngx_http_cephfs_readline_module.c
 * Create Date: 2018-11-02
 *
 */
#include "ngx_http_cephfs_readline_handler.h"


static ngx_int_t
ngx_http_cephfs_readline_handler(ngx_http_request_t *r);

static void
ngx_http_cephfs_readline_request_body_handler(ngx_http_request_t *r);

static ngx_buf_t *
ngx_http_cephfs_readline_read_body(ngx_http_request_t *r);

static ngx_buf_t *
ngx_http_cephfs_readline_read_body_from_file(ngx_http_request_t *r);

static ngx_int_t
ngx_http_cephfs_readline_init(ngx_conf_t *cf);

static void *
ngx_http_cephfs_readline_create_loc_conf(ngx_conf_t *cf);

static char*
ngx_http_cephfs_readline_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t
ngx_http_cephfs_readline_init_process(ngx_cycle_t *cycle);

static void
ngx_http_cephfs_readline_exit_process(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_cephfs_readline_commands[] = {

    { ngx_string("cephfs_readline"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_cephfs_readline_conf_t, enable),
        NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_cephfs_readline_module_ctx = {
    NULL,                                         /* preconfiguration */
    ngx_http_cephfs_readline_init,                /* postconfiguration */

    NULL,                                         /* create main configuration */
    NULL,                                         /* init main configuration */

    NULL,                                         /* create server configuration */
    NULL,                                         /* merge server configuration */

    ngx_http_cephfs_readline_create_loc_conf,     /* create location configration */
    ngx_http_cephfs_readline_merge_loc_conf       /* merge location configration */
};

ngx_module_t ngx_http_cephfs_readline_module = {
    NGX_MODULE_V1,
    &ngx_http_cephfs_readline_module_ctx,         /* module context */
    ngx_http_cephfs_readline_commands,            /* module directives */
    NGX_HTTP_MODULE,                              /* module type */
    NULL,                                         /* init master */
    NULL,                                         /* init module */
    ngx_http_cephfs_readline_init_process,        /* init process */
    NULL,                                         /* init thread */
    NULL,                                         /* exit thread */
    ngx_http_cephfs_readline_exit_process,        /* exit process */
    NULL,                                         /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_cephfs_readline_handler(ngx_http_request_t *r)
{
    ngx_int_t                               rc;
    ngx_http_cephfs_readline_ctx_t          *ctx;
    ngx_http_cephfs_readline_conf_t         *lrcf;

    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_cephfs_readline_module);
    if ( lrcf == NULL ) {
        return NGX_DECLINED;
    }

    if ( lrcf->enable == NGX_CONF_UNSET || lrcf->enable == 0 ) {
        return NGX_DECLINED;
    }

    ctx = (ngx_http_cephfs_readline_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cephfs_readline_ctx_t));
        if ( ctx == NULL ) {
	    return NGX_ERROR;
	}
        ngx_http_set_ctx(r, ctx, ngx_http_cephfs_readline_module);
    }
            
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
    	"[cephfs_readline] ngx_http_cephfs_readline start");


    rc = ngx_http_read_client_request_body(r, ngx_http_cephfs_readline_request_body_handler);
    if ( rc >= NGX_HTTP_SPECIAL_RESPONSE ) {
        return rc;
    }


    return NGX_DONE;
}

static void
ngx_http_cephfs_readline_send_response(ngx_http_request_t *r, ngx_int_t code,
    ngx_str_t *content)
{
    ngx_int_t                               rc;
    ngx_buf_t				    *b;
    ngx_chain_t				    out;


    /* set the 'Content-type' header */
    ngx_str_set(&r->headers_out.content_type, "text/json");
    r->headers_out.status = code;

    r->headers_out.content_length_n = content->len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[cephfs_readline] ngx_send_header error  rc=[%d]", rc);
        ngx_http_finalize_request(r, rc);
        return;
    }
    
    if ( content->len == 0 ) {
        ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_FLUSH));
	return;
    }
    

    /* allocate a buffer for your response body */
    b = ngx_create_temp_buf(r->pool, content->len);
    if ( b == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[cephfs_readline] request_body malloc is failed");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* attach this buffer to the buffer chain */
    out.buf = b;
    out.next = NULL;

    /* adjust the pointers of the buffer */
    b->pos = content->data;
    b->last = content->data + content->len;
    b->memory = 1;    /* this buffer is in memory */
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */

    /* send the buffer chain of your response */
    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
}


static void
ngx_http_cephfs_readline_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t				    rc;
    ngx_int_t				    code;
    ngx_http_cephfs_readline_ctx_t          *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
        return;
    }

    if (r->method != NGX_HTTP_POST) {
        code = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        code = NGX_HTTP_NO_CONTENT;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "[cephfs_readline] request_body no content");
        goto finish;
    }

    if ( r->request_body != NULL && r->request_body->bufs != NULL ) {
        if ( r->request_body->temp_file ) {
            ctx->request_body = ngx_http_cephfs_readline_read_body_from_file(r);
        } else {
            ctx->request_body = ngx_http_cephfs_readline_read_body(r);
        }
    }

    if ( ctx->request_body == NULL ) {
	code = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "[cephfs_readline] request_body out of memory");
	goto finish;
    }

    //request process
    rc = ngx_http_cephfs_readline_request(r);
    if ( rc != NGX_OK ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "[cephfs_readline] cephfs_readline_request is error");
    }

    code = NGX_HTTP_OK;

finish:
    
    ngx_http_cephfs_readline_send_response(r, code, &ctx->response_body);
}

static ngx_buf_t *
ngx_http_cephfs_readline_read_body(ngx_http_request_t *r)
{
    size_t                                  len;
    ngx_buf_t                               *buf, *next, *body;
    ngx_chain_t                             *cl;

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        return buf;
    } else {
        next = cl->next->buf;
        len = (buf->last - buf->pos) + (next->last - next->pos);

        body = ngx_create_temp_buf(r->pool, len);
        if (body == NULL) {
            return NULL;
        }
        body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
        body->last = ngx_cpymem(body->last, next->pos, next->last - next->pos);
    }

    return body;
}

static ngx_buf_t *
ngx_http_cephfs_readline_read_body_from_file(ngx_http_request_t *r)
{
    size_t                                  len;
    ssize_t                                 size;
    ngx_buf_t                               *buf, *body;
    ngx_chain_t                             *cl;

    len = 0;
    cl = r->request_body->bufs;

    while (cl) {
        buf = cl->buf;
        if (buf->in_file) {
            len += buf->file_last - buf->file_pos;
        } else {
            len += buf->last - buf->pos;
        }
        cl = cl->next;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[cephfs_readline] read post body file size %ui", len);

    body = ngx_create_temp_buf(r->pool, len);
    if (body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[cephfs_readline] cannot allocate enough space to store the request body, request len [%d]", len);
        return NULL;
    }
    cl = r->request_body->bufs;

    while (cl) {
        buf = cl->buf;
        if (buf->in_file) {
            size = ngx_read_file(buf->file, body->last,
                                 buf->file_last - buf->file_pos, buf->file_pos);
            if (size == NGX_ERROR) {
                return NULL;
            }
            body->last += size;
        } else {
            body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
        }
        cl = cl->next;
    }
    return body;
}

static void *
ngx_http_cephfs_readline_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cephfs_readline_conf_t      *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cephfs_readline_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char*
ngx_http_cephfs_readline_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cephfs_readline_conf_t      *prev = parent;
    ngx_http_cephfs_readline_conf_t      *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_cephfs_readline_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt                     *h;
    ngx_http_core_main_conf_t               *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_cephfs_readline_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cephfs_readline_init_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "[cephfs_readline] init process");

    return ngx_http_cephfs_readline_start(cycle);
}


static void
ngx_http_cephfs_readline_exit_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "[cephfs_readline] exit process");

    ngx_http_cephfs_readline_exit(cycle);
}

