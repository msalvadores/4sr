#ifndef _4SR_QUERY_H  /* duplication check */
#define _4SR_QUERY_H

#include "common/4store.h"

typedef struct {
    fs_rid_vector **subClassOf_bind;
    unsigned char *subClassOf_msg;
    fs_rid_vector **subProperty_bind;
    unsigned char *subProperty_msg;
    fs_rid_vector **range_bind;
    unsigned char *range_msg;
    fs_rid_vector **domain_bind;
    unsigned char *domain_msg;

    GHashTable *quad_assignment;
} reasoner_cache;

/*
fs_rid_vector **rdfs_subclass_stmts(fsp_link *link);
fs_rid_vector **rdfs_subproperty_stmts(fsp_link *link);
fs_rid_vector **rdfs_range_stmts(fsp_link *link);
fs_rid_vector **rdfs_domain_stmts(fsp_link *link);
void print_binding(fs_rid_vector **b,int cols);
*/
reasoner_cache *fsr_load_reasoner_cache(fsp_link *link);
reasoner_cache *fsr_get_reasoner_cache();
int fsr_init_reasoner (fsp_link* link);
int fsr_reasoning_level_flag(const char *v);
gchar *fsr_reasoning_level_string(int flag);
#endif
