

void notify_import_finished(reasoner_conf *reasoner);
fs_rid_vector *rdfs_sub_properties(reasoner_conf *reasoner,fs_rid *node);
fs_rid_vector *rdfs_subproperties_vector(reasoner_conf *reasoner,fs_rid_vector *nodes);

fs_rid_vector *rdfs_sub_classes(reasoner_conf *reasoner,fs_rid *node);
fs_rid_vector *rdfs_sub_classes_vector(reasoner_conf *reasoner,fs_rid_vector *nodes);

int rdfs_extend_quads(reasoner_conf *reasoner,const fs_rid source_quad[],fs_rid_vector **bind_target, 
                      int bind_flags,int limit,int *count);

