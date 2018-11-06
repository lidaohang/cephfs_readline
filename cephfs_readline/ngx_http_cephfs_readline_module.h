#ifndef __NGX_HTTP_CEPHFS_READLINE_MODULE_H__
#define __NGX_HTTP_CEPHFS_READLINE_MODULE_H__


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t       filename;
    ngx_str_t       poolname;
    ngx_int_t       offset;
    ngx_str_t       object_name;
    ngx_str_t       line;
    ngx_int_t       dest_offset;

    ngx_int_t       next;
    ngx_int_t	    next_offset;
    ngx_str_t       next_object_name;
    ngx_str_t       next_line;
    ngx_int_t       next_dest_offset;

    ngx_str_t       body;
    ngx_str_t       response_body;
    ngx_buf_t       *request_body;

    ngx_int_t	    code;
    ngx_int_t	    cost;
} ngx_http_cephfs_readline_ctx_t;


typedef struct {
    ngx_flag_t      enable;
} ngx_http_cephfs_readline_conf_t;


#endif /* __NGX_HTTP_CEPHFS_READLINE_MODULE_H__ */

