/*
 * Author: lihang <lihang_net@126.com>
 *
 * File: ngx_http_cephfs_readline_handler.c
 * Create Date: 2018-11-02
 *
 */
#include "ngx_http_cephfs_readline_handler.h"

#include "ngx_http_cephfs_readline_handler.h"

#include <rados/librados.h>
#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#include "ioctl.h"

static const size_t  line_size = 1024;
static const size_t  object_size = 4194304;

static ngx_int_t
ngx_http_cephfs_request_parser(ngx_http_request_t *r);

static ngx_int_t
ngx_http_cephfs_response_body(ngx_http_request_t *r);



static ngx_int_t
ngx_http_cephfs_get_object_offset(const size_t offset)
{
    size_t                                  object_count;

    object_count = offset / object_size;
    return (offset - object_count * object_size);
}

static ngx_int_t
ngx_http_cephfs_get_object_name(ngx_http_request_t *r)
{
    int                               	    fd, err;
    struct                                  ceph_ioctl_dataloc dl;
    ngx_http_cephfs_readline_ctx_t          *ctx;


    ctx = (ngx_http_cephfs_readline_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
        return NGX_ERROR;
    }

    if ( ctx->filename.data == NULL || ctx->filename.len == 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] filename is empty");
        return NGX_ERROR;
    }
    ctx->filename.data[ctx->filename.len] = 0;    

    fd = open((char*)ctx->filename.data, O_RDONLY, 0644);
    if ( fd < 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] open() filename=[%s] failed error=[%s]", ctx->filename.data,  strerror(fd));
        return NGX_ERROR;
    }

    if ( ctx->next ) {
        dl.file_offset = ctx->next_offset;
    }else {
        dl.file_offset = ctx->offset;
    }
    err = ioctl(fd, CEPH_IOC_GET_DATALOC, (unsigned long)&dl);
    if ( err < 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] error: getting location [%s]", strerror(err));
        return NGX_ERROR;
    }

    if ( ctx->next ) {
        ctx->next_object_name.len = strlen(dl.object_name);
        ctx->next_object_name.data = (u_char*)ngx_pcalloc(r->pool, ctx->next_object_name.len + 1);
        if ( ctx->next_object_name.data == NULL ) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[cephfs_readline] ctx->object_name.data malloc is failed");

            close(fd);
            return NGX_ERROR;
        }
        ngx_memcpy(ctx->next_object_name.data, dl.object_name, ctx->next_object_name.len);
        ctx->next_object_name.data[ctx->next_object_name.len] = 0;       

        close(fd);
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "[cephfs_readline] object_name.len=[%d] object_name.data=[%s]", ctx->next_object_name.len, ctx->next_object_name.data);

        return NGX_OK;
    }

    ctx->object_name.len = strlen(dl.object_name);
    ctx->object_name.data = (u_char*)ngx_pcalloc(r->pool, ctx->object_name.len + 1);
    if ( ctx->object_name.data == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] ctx->object_name.data malloc is failed");

        close(fd);
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->object_name.data, dl.object_name, ctx->object_name.len);
    ctx->object_name.data[ctx->object_name.len] = 0;

    close(fd);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "[cephfs_readline] object_name.len=[%d] object_name.data=[%s]", ctx->object_name.len, ctx->object_name.data);

    return NGX_OK;
}

static ngx_int_t
ngx_http_cephfs_get_rados_line(ngx_http_request_t *r)
{
    int                                     err;	
    char                                    buffer[line_size];
    ngx_uint_t                              flags = 0;
    ngx_uint_t                              offset;
    rados_t                                 cluster;
    rados_ioctx_t                           io;
    rados_completion_t                      comp;
    ngx_str_t                               cluster_name = ngx_string("ceph");
    ngx_str_t                               ceph_conf = ngx_string("/etc/ceph/ceph.conf");
    ngx_str_t                               user_name = ngx_string("client.admin");
    ngx_http_cephfs_readline_ctx_t          *ctx;


    ctx = (ngx_http_cephfs_readline_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
        return NGX_ERROR;
    }

    if ( ctx->poolname.data == NULL || ctx->poolname.len == 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] poolname is empty");
        return NGX_ERROR;
    }

     /* Initialize the cluster handle with the "ceph" cluster name and the "client.admin" user */
    err = rados_create2(&cluster, (char *)cluster_name.data, (char* ) user_name.data, flags);
    if ( err < 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] couldn't create the cluster handle poolname=[%s] object_name=[%s] error=[%s]",
            ctx->poolname.data, ctx->object_name.data, strerror(-err));
        return NGX_ERROR;
    }

    /* Read a Ceph configuration file to configure the cluster handle. */
    err = rados_conf_read_file(cluster, (char *)ceph_conf.data);
    if ( err < 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] cannot read config file poolname=[%s] object_name=[%s] error=[%s]",
            ctx->poolname.data, ctx->object_name.data, strerror(-err));
        return NGX_ERROR;
    }

    /* Connect to the cluster */
    err = rados_connect(cluster);
    if ( err < 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] cannot connect to cluster poolname=[%s] object_name=[%s] error=[%s]",
            ctx->poolname.data, ctx->object_name.data,  strerror(-err));
        return NGX_ERROR;
    }

    //create io
    ctx->poolname.data[ctx->poolname.len] = 0;

    err = rados_ioctx_create(cluster, (char *)ctx->poolname.data, &io);
    if ( err < 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] cannot open rados pool poolname=[%s] object_name=[%s] error=[%s]",
            ctx->poolname.data, ctx->object_name.data, strerror(-err));

        rados_shutdown(cluster);
        return NGX_ERROR;
    }

    /*
     * Read data from the cluster asynchronously.
     * First, set up asynchronous I/O completion.
     */
    err = rados_aio_create_completion(NULL, NULL, NULL, &comp);
    if ( err < 0 ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] could not create aio completion poolname=[%s] object_name=[%s] error=[%s]",
            ctx->poolname.data, ctx->object_name.data, strerror(-err));

        rados_ioctx_destroy(io);
        rados_shutdown(cluster);
        return NGX_ERROR;
    }

    offset = ctx->next ? ctx->next_dest_offset : ctx->dest_offset;

    /* Next, read data using rados_aio_read. */
    err = rados_aio_read(io, (char *)ctx->object_name.data, comp, buffer, line_size, offset);
    if (err < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] cannot read object poolname=[%s] object_name=[%s] offset=[%d] error=[%s]",
            ctx->poolname.data, ctx->object_name.data, ctx->offset, strerror(-err));

        rados_ioctx_destroy(io);
        rados_shutdown(cluster);
        return NGX_ERROR;
    }
    /* Wait for the operation to complete */
    rados_aio_wait_for_complete(comp);
    /* Release the asynchronous I/O complete handle to avoid memory leaks. */
    rados_aio_release(comp);

    rados_ioctx_destroy(io);
    rados_shutdown(cluster);

    if ( ctx->next ) {
        ctx->next_line.len = strlen(buffer);
        ctx->next_line.data = ngx_pcalloc(r->pool, ctx->next_line.len);
        if ( ctx->next_line.data == NULL ) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[cephfs_readline] ctx->next_line.data malloc is failed");
            return NGX_ERROR;
        }
        ngx_memcpy(ctx->next_line.data, buffer, ctx->next_line.len);

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "[cephfs_readline] next_line.len=[%d] next_line.data=[%s]", ctx->next_line.len, ctx->next_line.data);
        return NGX_OK;
    }

    ctx->line.len = strlen(buffer);
    ctx->line.data = ngx_pcalloc(r->pool, ctx->line.len);
    if ( ctx->line.data == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] ctx->next_line.data malloc is failed");
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->line.data, buffer, ctx->line.len);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "[cephfs_readline] line.len=[%d] line.data=[%s]", ctx->line.len, ctx->line.data);
    return NGX_OK;
}


static ngx_int_t
ngx_http_cephfs_readline_process(ngx_http_request_t *r)
{
    ngx_int_t                              rc;
    ngx_http_cephfs_readline_ctx_t         *ctx;


    ctx = (ngx_http_cephfs_readline_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
        return NGX_ERROR;
    }

    //get object_name
    rc = ngx_http_cephfs_get_object_name(r);
    if ( rc != NGX_OK ) {
        return NGX_ERROR;
    }

    //get object_name offset
    if ( ctx->next ) {
        ctx->next_dest_offset = ngx_http_cephfs_get_object_offset(ctx->next_offset);
    }else {
        ctx->dest_offset = ngx_http_cephfs_get_object_offset(ctx->offset);
    }

    //get rados readline
    rc = ngx_http_cephfs_get_rados_line(r);
    if ( rc != NGX_OK ) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_cephfs_readline_request(ngx_http_request_t *r)
{
    char				*p;
    ngx_int_t                           rc;
    struct timeval                      tv;
    ngx_http_cephfs_readline_ctx_t      *ctx;


    ctx = (ngx_http_cephfs_readline_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
        ctx->code = NGX_ERROR;
        goto done;
    }

    rc = ngx_http_cephfs_request_parser(r);
    if ( rc != NGX_OK ) {
        ctx->code = NGX_ERROR;
        goto done;
    }

    rc = ngx_http_cephfs_readline_process(r);
    if ( rc != NGX_OK ) {
        ctx->code = NGX_ERROR;
        goto done;
    }

    if ( ctx->line.len == line_size ) {
        ctx->body.data = ctx->line.data;
        ctx->body.len  = ctx->line.len;
        ctx->code = NGX_OK;
        goto done;
    }

    if ((p = strchr((char*)ctx->line.data, '\n')) != NULL) {
        *p = '\0';
        ctx->body.data = ctx->line.data;
        ctx->body.len  = strlen((char*)ctx->body.data);
        ctx->code = NGX_OK;
        goto done;
    }

    //next object_name
    ctx->next = 1;
    ctx->next_offset = ctx->offset + 1024;
    rc = ngx_http_cephfs_readline_process(r);
    if ( rc != NGX_OK ) {
        ctx->code = NGX_ERROR;
        goto done;
    }

    if ((p = strchr((char*)ctx->next_line.data, '\n')) != NULL) {
        *p = '\0';

        ctx->body.len = ctx->line.len + strlen((char*)ctx->next_line.data);
        ctx->body.data = ngx_pcalloc(r->connection->pool, ctx->body.len);
        if ( ctx->body.data != NULL ) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[cephfs_readline] ctx->body.data malloc is failed");
            ctx->code = NGX_ERROR;
            goto done;
        }
        ngx_sprintf(ctx->body.data, "%s%s", ctx->line.data, ctx->next_line.data);
        ctx->code = NGX_OK;
        goto done;
    }

    ctx->body.len = ctx->line.len + (line_size - ctx->line.len);
    ctx->body.data = ngx_pcalloc(r->connection->pool, ctx->body.len);
    if ( ctx->body.data != NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[cephfs_readline] ctx->body.data malloc is failed");
        ctx->code = NGX_ERROR;
        goto done;
    }
    strncpy((char*)ctx->body.data, (char*)ctx->line.data, ctx->line.len);
    strncpy((char*)ctx->body.data, (char*)ctx->next_line.data, line_size - ctx->line.len);

done:
    ngx_gettimeofday(&tv);
    ctx->cost = (tv.tv_sec - r->start_sec) * 1000
		    + (tv.tv_usec / 1000 - r->start_msec);

    rc  = ngx_http_cephfs_response_body(r);
    if ( rc != NGX_OK ) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cephfs_response_body(ngx_http_request_t *r)
{
    size_t				len;
    const unsigned char 		*buf;
    yajl_gen                            g;
    ngx_http_cephfs_readline_ctx_t      *ctx;


    ctx = (ngx_http_cephfs_readline_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
        ctx->code = NGX_ERROR;
        return NGX_ERROR;
    }

    g = yajl_gen_alloc(NULL);
    if ( g == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] yajl_gen_alloc is null");
        return NGX_ERROR;
    }
    yajl_gen_config(g, yajl_gen_beautify, 0);

    yajl_gen_map_open(g);

    yajl_gen_string(g, (const unsigned char *) NGX_HTTP_CEPHFS_READLINE_CODE, strlen(NGX_HTTP_CEPHFS_READLINE_CODE));
    yajl_gen_integer(g, ctx->code);

    yajl_gen_string(g, (const unsigned char *) NGX_HTTP_CEPHFS_READLINE_COST, strlen(NGX_HTTP_CEPHFS_READLINE_COST));
    yajl_gen_integer(g, ctx->cost);

    yajl_gen_string(g, (const unsigned char *) NGX_HTTP_CEPHFS_READLINE_DATA, strlen(NGX_HTTP_CEPHFS_READLINE_DATA));
    yajl_gen_string(g, ctx->body.data, ctx->body.len);

    yajl_gen_map_close(g);

    yajl_gen_status status = yajl_gen_get_buf(g, &buf, &len);
    if(status != yajl_gen_status_ok) {
        yajl_gen_free(g);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] yajl_gen_get_buf is null");
        return NGX_ERROR;
    }

    ctx->response_body.len = len;
    ctx->response_body.data = (u_char*)ngx_pcalloc(r->pool, ctx->response_body.len);
    if ( ctx->response_body.data == NULL ) {
        yajl_gen_free(g);
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->response_body.data, buf, ctx->response_body.len);
    yajl_gen_free(g);

    return NGX_OK;
}

static ngx_int_t
ngx_http_cephfs_request_parser(ngx_http_request_t *r)
{
    yajl_val                                node;
    ngx_http_cephfs_readline_ctx_t          *ctx;


    ctx = (ngx_http_cephfs_readline_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_cephfs_readline_module);
    if ( ctx == NULL ) {
        return NGX_ERROR;
    }
    ctx->request_body->pos[ctx->request_body->last - ctx->request_body->pos] = 0;

    node = yajl_tree_parse((char*)ctx->request_body->pos, NULL, 0);
    if (( node == NULL ) || (!YAJL_IS_OBJECT(node))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] yajl_tree_parse is null");
        return NGX_ERROR;
    }

    const yajl_val filename = yajl_tree_get(node , (const char*[]){NGX_HTTP_CEPHFS_READLINE_FILENAME, 0}, yajl_t_string);
    const yajl_val poolname = yajl_tree_get(node , (const char*[]){NGX_HTTP_CEPHFS_READLINE_POOLNAME, 0}, yajl_t_string);
    const yajl_val offset = yajl_tree_get(node , (const char*[]){NGX_HTTP_CEPHFS_READLINE_OFFSET, 0}, yajl_t_number);

    if ( !filename || !poolname || !offset ) {
        yajl_tree_free(node);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] yajl_tree_parse json fromat illegal");
        return NGX_ERROR;
    }

    const char *filename_buf = YAJL_GET_STRING(filename);
    if ( filename_buf == NULL ) {
        yajl_tree_free(node);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] yajl_tree_parse json fromat illegal filenme is empty");
        return NGX_ERROR;
    }

    ctx->filename.len = strlen(filename_buf);
    ctx->filename.data = ngx_pcalloc(r->pool, ctx->filename.len);
    if ( ctx->filename.data == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] ctx->filename malloc is failed");
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->filename.data, filename_buf, ctx->filename.len);

    
    const char *poolname_buf = YAJL_GET_STRING(poolname);
    if ( poolname_buf == NULL ) {
        yajl_tree_free(node);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] yajl_tree_parse json fromat illegal poolname is empty");
        return NGX_ERROR;
    }

    ctx->poolname.len = strlen(poolname_buf);
    ctx->poolname.data = ngx_pcalloc(r->pool, ctx->poolname.len);
    if ( ctx->poolname.data == NULL ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[cephfs_readline] ctx->poolname malloc is failed");
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->poolname.data, poolname_buf, ctx->poolname.len);

    ctx->offset = YAJL_GET_INTEGER(offset);

    return NGX_OK;
}

