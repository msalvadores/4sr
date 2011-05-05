#ifndef _4SR_BACK_H  /* duplication check */
#define _4SR_BACK_H

#include "4s-reasoner-common.h"

fs_rid_vector *fsr_rdfs_sub_properties(fs_rid *node);
fs_rid_vector *fsr_rdfs_subproperties_vector(fs_rid_vector *nodes);

fs_rid_vector *fsr_rdfs_sub_classes(fs_rid *node);
fs_rid_vector *fsr_rdfs_sub_classes_vector(fs_rid_vector *nodes);

int fsr_rdfs_extend_quads(const fs_rid source_quad[],GPtrArray *entailments, 
                      int bind_flags,int limit,int *count, int reasoning);
int fsr_rdfs_extend_quads_domain_range(GHashTable *preds_by_subj,fs_rid_vector *subject, 
                             fs_rid_vector *objects,GPtrArray *entailments,int bind_flags,int *count);
GHashTable *fsr_get_rdfs_domains();
GHashTable *fsr_get_rdfs_ranges();
guint fsr_add_elto_set(GHashTable* lookup,fs_rid *rid,fs_rid_vector *eltos);
int fsr_controlled_append(GPtrArray *list,fs_rid *quad);
fs_rid *fsr_get_new_quad_for(fs_rid m,fs_rid s,fs_rid p,fs_rid o);
unsigned char *fsr_handle_update_cache(fs_segment segment,unsigned int length, unsigned char *content, int type);
void fsr_print_cache_stats();
void fsr_dump_table(GHashTable *table);
gboolean fsr_rid_equal(fs_rid *v1,fs_rid *v2);
guint fsr_rid_hash(fs_rid *v);
void fsr_set_class_membership_dr(GHashTable *l,fs_rid_vector *k);
class_membership_dr *fsr_get_class_membership_dr();
#endif
