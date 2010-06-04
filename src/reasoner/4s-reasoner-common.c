
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>

#include "common/4s-internals.h"
#include "common/datatypes.h"
#include "common/params.h"
#include "common/error.h"


unsigned char *reasoner_recv(int conn,unsigned int* bytes_read) {
    int err;
    unsigned char header[FS_HEADER];
    unsigned char *buffer, *p;
    unsigned int * const l = (unsigned int *) (header + 4);
    unsigned int len;

    err= recv(conn, header, FS_HEADER, 0);
    if (err < 0) {
        fs_error(LOG_ERR, "recv header from socket failed, %s", strerror(errno));
        return NULL;
    } else if (err == 0) {
        return NULL;
    }
    //length of the message comming at header + 4
    len = *l;
    //returning by ref as well
    *bytes_read = len;
    //buffer memory for header plus len of message
    buffer = calloc(1, FS_HEADER + len);
    memcpy(buffer,header,FS_HEADER);
    //seek pointer to data start
    p = buffer+ FS_HEADER;
    while(len > 0) {
        int count = recv(conn,p,len, 0);
        if (count <= 0) {
            fs_error(LOG_ERR, "recv body from socket failed, %s", strerror(errno));
            break;
        }
        p += count;
        len -= count;
    }
    return buffer;
}

unsigned char * list_integer_msg(int type,GList *list) {
    guint nlist = g_list_length(list);
	size_t data_length = nlist * sizeof(int);
	unsigned char *buffer = calloc(1, FS_HEADER + data_length);
	unsigned int * const l = (unsigned int *) (buffer + 4);
	*l = (unsigned int) data_length;
	//printf("[mtrx2msg] data_length %i\n",*l);
	buffer[3] = (unsigned char) type;
	unsigned char *data = buffer + FS_HEADER;
    GList *tmp=list;
    int *elt=NULL;
    while(tmp) {
      elt = calloc(1,sizeof(int));
      *elt = GPOINTER_TO_INT(tmp->data);
	  memcpy(data, elt, sizeof(int));
      data += sizeof(int);
      tmp=g_list_next(tmp);
    }
	return buffer;
}

unsigned char * mtrx_to_msg(int type,fs_rid_vector **mtx,int cols) {
	if (mtx == NULL)
		return NULL;
	size_t data_length = mtx[0]->length * 8 * cols;
	unsigned char *buffer = calloc(1, FS_HEADER + data_length);
	unsigned int * const c = (unsigned int *) (buffer + 8);
	unsigned int * const l = (unsigned int *) (buffer + 4);
	*c = (int) cols;
	*l = (unsigned int) data_length;
	buffer[3] = (unsigned char) type;
	unsigned char *data = buffer + FS_HEADER;
	int k;	
	for (k= 0; k < cols; ++k) {
	  memcpy(data, mtx[k]->data, mtx[k]->length * 8);
	  data += mtx[k]->length * 8;
	}
	return buffer;
}

fs_rid_vector **msg_to_mtrx(unsigned char *msg) {
	int k;
	fs_rid_vector **result;
	int cols = *((int *) (msg + 8));
	unsigned int data_length = *((unsigned int *) (msg + 4));
	//printf("[msg2mtrx] data_length %i cols %i\n",data_length,cols);
	unsigned char *content = msg + FS_HEADER;

    result = calloc(cols, sizeof(fs_rid_vector *));
	int count = data_length / (8 * cols);
    for (k = 0; k < cols; ++k) {
		fs_rid_vector *v = fs_rid_vector_new(count);
		result[k] = v;
		memcpy(v->data, content, count * 8);
		content += count * 8;
    }
	return result;
}
