

void notify_import_finished(reasoner_conf *reasoner);
fs_rid_vector *rdfs_sub_properties(reasoner_conf *reasoner,fs_rid *node);
fs_rid_vector *rdfs_subproperties_vector(reasoner_conf *reasoner,fs_rid_vector *nodes);

fs_rid_vector *rdfs_sub_classes(reasoner_conf *reasoner,fs_rid *node);
fs_rid_vector *rdfs_sub_classes_vector(reasoner_conf *reasoner,fs_rid_vector *nodes);

int rdfs_extend_quads(reasoner_conf *reasoner,const fs_rid source_quad[],GList **entailments, 
                      int bind_flags,int limit,int *count);
int rdfs_extend_quads_domain(reasoner_conf *reasoner, GHashTable *preds_by_subj,fs_rid_vector *subject, 
                             fs_rid_vector *objects,GList **entailments,int bind_flags,int *count);
GHashTable *get_rdfs_domains(reasoner_conf *reasoner);
GHashTable *get_rdfs_ranges(reasoner_conf *reasoner);
void add_elto_set(GHashTable* lookup,fs_rid *rid,fs_rid_set *eltos);
gboolean fs_rid_equal(fs_rid *v1,fs_rid *v2);
guint fs_rid_hash(fs_rid *v);
int controlled_append(GList **list,fs_rid *quad);
fs_rid *get_new_quad_for(fs_rid m,fs_rid s,fs_rid p,fs_rid o);
GList *get_equads_assignment(fs_segment segment,GList *entailments,reasoner_conf *reasoner);
