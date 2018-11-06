CC = gcc
CEPH_LIB =  -L/home/rpmbuild/BUILD/ceph-12.2.8.1/build/lib/ -lrados
CEPH_INCLUDE = -I/home/rpmbuild/BUILD/ceph-12.2.8.1/src/include -I/home/rpmbuild/BUILD/ceph-12.2.8.1/src/ -I/home/rpmbuild/BUILD/ceph-12.2.8.1/build/include/ -I/home/rpmbuild/BUILD/ceph-12.2.8.1/src/client/

all:
	$(CC) -g ceph_fileline.c $(CEPH_LIB) -o ceph-fileline  $(CEPH_INCLUDE)


