
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>

#include "common/4s-internals.h"
#include "common/4s-datatypes.h"
#include "common/params.h"
#include "common/error.h"

static unsigned char fsp_vermagic[4] = { 'I', 'D', FS_PROTO_VER_MINOR, 0x0 };

unsigned char * fsr_mtrx_to_msg(int type,fs_rid_vector **mtx,int cols) {
	if (mtx == NULL)
		return NULL;
	size_t data_length = mtx[0]->length * 8 * cols;
	unsigned char *buffer = calloc(1, FS_HEADER + data_length);
    
    memcpy(buffer, fsp_vermagic, 3);

	unsigned int * const c = (unsigned int *) (buffer + 12);
	unsigned int * const l = (unsigned int *) (buffer + 4);
	*c = (int) cols;
	*l = (unsigned int) data_length;
    //printf("mtrx_to_msg mtx[0]->length %u data_length %u\n",mtx[0]->length,data_length);
	buffer[3] = (unsigned char) type;
	unsigned char *data = buffer + FS_HEADER;
	int k;	
	for (k= 0; k < cols; ++k) {
	  memcpy(data, mtx[k]->data, mtx[k]->length * 8);
	  data += mtx[k]->length * 8;
	}
	return buffer;
}

fs_rid_vector **fsr_msg_to_mtrx(unsigned char *msg) {
	int k;
	fs_rid_vector **result;
	int cols = *((int *) (msg + 12));
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
