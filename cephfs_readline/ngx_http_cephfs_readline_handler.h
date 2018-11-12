#ifndef __NGX_HTTP_CEPHFS_READLINE_HANDLER_H__
#define __NGX_HTTP_CEPHFS_READLINE_HANDLER_H__

#include "ngx_http_cephfs_readline_module.h"


#define NGX_HTTP_CEPHFS_READLINE_FILENAME   "filename"
#define NGX_HTTP_CEPHFS_READLINE_POOLNAME   "poolname"
#define NGX_HTTP_CEPHFS_READLINE_OFFSET     "offset"
#define NGX_HTTP_CEPHFS_READLINE_CODE       "code"
#define NGX_HTTP_CEPHFS_READLINE_COST       "cost"
#define NGX_HTTP_CEPHFS_READLINE_DATA       "data"


extern ngx_module_t ngx_http_cephfs_readline_module;

ngx_int_t
ngx_http_cephfs_readline_start(ngx_cycle_t *cycle);

void
ngx_http_cephfs_readline_exit(ngx_cycle_t *cycle);

ngx_int_t
ngx_http_cephfs_readline_request(ngx_http_request_t *r);


#endif /* __NGX_HTTP_CEPHFS_READLINE_HANDLER_H__ */
