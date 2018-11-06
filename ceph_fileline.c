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
#include <string.h>

#include <rados/librados.h>
#include "ioctl.h"


#define     DSS_OK          0
#define     DSS_ERROR       -1


static const int object_size = 4194304;



static
int get_object_offset(const size_t src_offset) {
    size_t                             object_count;
    size_t                             object_offset;;

    object_count = src_offset / object_size;
    return (src_offset - object_count * object_size);
}


static
int get_object_name(const char *filename,const size_t offset, char *dest_object_name) {

    int                                 fd, err;
    struct                              ceph_ioctl_layout l;
    struct                              ceph_ioctl_dataloc dl;


    fd = open(filename, O_RDONLY, 0644);
    if (fd < 0) {
        printf("error: open() filename=[%s] failed with   error=[%s]\n",filename,  strerror(fd));
        return DSS_ERROR;
    }

    dl.file_offset = offset;
    err = ioctl(fd, CEPH_IOC_GET_DATALOC, (unsigned long)&dl);
    if (err < 0) {
        printf("error: getting location [%s]\n", strerror(err));
        return DSS_ERROR;
    }

    if (dl.object_name == NULL || strlen(dl.object_name) <= 0) {
        printf("error: dl.object_name is zero  file_name=[%s] offset=[%d]",  filename, offset);
        return DSS_ERROR;
    }

    memcpy(dest_object_name, dl.object_name, strlen(dl.object_name) + 1);


    close(fd);

    return DSS_OK;
}

static
int get_rados_line(const char *poolname, const char *object_name, const size_t offset, const size_t line_size, char *line) {

    /* Declare the cluster handle and required arguments. */
    int                                 err;
    char                                cluster_name[] = "ceph";
    char                                user_name[] = "client.admin";
    uint64_t                            flags = 0;
    rados_t                             cluster;
    rados_ioctx_t                       io;
    rados_completion_t                  comp;


    /* Initialize the cluster handle with the "ceph" cluster name and the "client.admin" user */
    err = rados_create2(&cluster, cluster_name, user_name, flags);
    if (err < 0) {
            fprintf(stderr, "error: couldn't create the cluster handle poolname=[%s] object_name=[%s] offset=[%d] error=[%s]\n",
			poolname, object_name, offset, strerror(-err));
            return DSS_ERROR;
    }

    /* Read a Ceph configuration file to configure the cluster handle. */
    err = rados_conf_read_file(cluster, "/etc/ceph/ceph.conf");
    if (err < 0) {
            fprintf(stderr, "error: cannot read config file poolname=[%s] object_name=[%s] offset=[%d] error=[%s]\n",
			poolname, object_name, offset,  strerror(-err));
            return DSS_ERROR;
    }

    /* Connect to the cluster */
    err = rados_connect(cluster);
    if (err < 0) {
            fprintf(stderr, "error: cannot connect to cluster poolname=[%s] object_name=[%s] offset=[%d] error=[%s]\n",
			poolname, object_name, offset,  strerror(-err));
            return DSS_ERROR;
    }

    //create io
    err = rados_ioctx_create(cluster, poolname, &io);
    if (err < 0) {
            fprintf(stderr, "error: cannot open rados pool poolname=[%s] object_name=[%s] offset=[%d] error=[%s]\n",
			poolname, object_name, offset, strerror(-err));
            rados_shutdown(cluster);
            return DSS_ERROR;
    }

    /*
     * Read data from the cluster asynchronously.
     * First, set up asynchronous I/O completion.
     */
    err = rados_aio_create_completion(NULL, NULL, NULL, &comp);
    if (err < 0) {
            fprintf(stderr, "error: could not create aio completion poolname=[%s] object_name=[%s] offset=[%d] error=[%s]\n",
			poolname, object_name, offset, strerror(-err));
            rados_ioctx_destroy(io);
            rados_shutdown(cluster);
            return DSS_ERROR;
    }

    /* Next, read data using rados_aio_read. */
    err = rados_aio_read(io, object_name, comp, line, line_size, offset);
    if (err < 0) {
            fprintf(stderr, "error: cannot read object poolname=[%s] object_name=[%s] offset=[%d] error=[%s]\n",
			poolname, object_name, offset, strerror(-err));
            rados_ioctx_destroy(io);
            rados_shutdown(cluster);
            return DSS_ERROR;
    }
    /* Wait for the operation to complete */
    rados_aio_wait_for_complete(comp);
    /* Release the asynchronous I/O complete handle to avoid memory leaks. */
    rados_aio_release(comp);

    rados_ioctx_destroy(io);
    rados_shutdown(cluster);

    return DSS_OK;
}

static
int handler(const char *poolname, const char *filename, size_t offset, size_t line_size, char *line) {
    int                             rc;
    size_t			    dest_offset;
    char                            object_name[20];

    //get object_name
    rc = get_object_name(filename, offset, object_name);
    if (rc == DSS_ERROR) {
        return DSS_ERROR;
    }

    //get object_name offset
    dest_offset = get_object_offset(offset);

    rc = get_rados_line(poolname, object_name, dest_offset, line_size,  line);
    if (rc == DSS_ERROR) {
        return DSS_ERROR;
    }

    return DSS_OK;
}


int main(int argc, char **argv)
{
    int                             rc;
    size_t			    line_size = 1024;
    char                            *filename;
    char                            *poolname;
    size_t                          offset;
    char                            line[line_size], next_object_line[line_size], *p;

    if (argc != 4) {
        printf("usage: dss_readfile <poolname> <filename> <offset>\n");
        return 1;
    }

    poolname = argv[1];
    filename = argv[2];
    offset = atoll(argv[3]);

    rc = handler(poolname, filename, offset, line_size, line);
    if (rc == DSS_ERROR) {
	return 1;
    }

    if (strlen(line) == line_size) {
    	printf("success: %s", line);
    	return 0;
    }

    if ((p = strchr(line, '\n')) != NULL) {
	*p = '\0';
    	printf("success: %s", line);
    	return 0;
    }

    //next object_name
    offset = offset + 1024;
    rc = handler(poolname, filename, offset, line_size, next_object_line);
    if (rc == DSS_ERROR) {
	return 1;
    }

    if ((p = strchr(next_object_line, '\n')) != NULL) {
	*p = '\0';
    	printf("success: %s%s", line, next_object_line);
    	return 0;
    }

    strncpy(line, next_object_line, line_size - strlen(line));

    printf("success: %s", line);
    return 0;
}

