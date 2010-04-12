
#include "common/datatypes.h"

#define RS_GBL_SUBCLASS 0x51
#define RS_GBL_SUBCLASS_RESP 0x52

#define RS_GBL_SUBPROPERTY 0x53
#define RS_GBL_SUBPROPERTY_RESP 0x54

#define RS_NOTIFY_IMPORT 0x55
#define RS_NOTIFY_IMPORT_RESP 0x56

#define TRAVERSE_UP 0
#define TRAVERSE_DOWN 1

#define RDF_TYPE_RID 0xE95E3998E1FB6613
#define RDFS_SUBCLASS_RID 0xDB1EFEADA54C0B14
#define RDFS_SUBPROPERTY_RID 0xFFAFB93495896EEF

#define RDFS_SUBCLASS_XXPX 0x0001
#define RDFS_SUBCLASS_XXPO 0x0002

#define DEBUG_RDFS 1

unsigned char * mtrx_to_msg(int type,fs_rid_vector **mtx,int cols);
fs_rid_vector **msg_to_mtrx(unsigned char *msg);
unsigned char *reasoner_recv(int conn,unsigned int* bytes_read);
