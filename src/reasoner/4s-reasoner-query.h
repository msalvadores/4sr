
#include "common/4store.h"

typedef struct {
    fs_rid_vector **subClassOf_bind;
    unsigned char *subClassOf_msg;
    fs_rid_vector **subProperty_bind;
    unsigned char *subProperty_msg;
} reasoner_cache;

fs_rid_vector **rdfs_subclass_stmts(fsp_link *link);
fs_rid_vector **rdfs_subproperty_stmts(fsp_link *link);
void print_binding(fs_rid_vector **b,int cols);
