
#include "common/4s-internals.h"

#include "common/4s-datatypes.h"
#include "common/params.h"
#include "common/error.h"
#include "4s-reasoner-common.h"
#include "4s-reasoner-query.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

static reasoner_cache fsr_cache;

int fsr_reasoning_level_flag(const char *v) {
    for (int i=0; i < strlen(v);i++) {
        if (v[i] != FSR_SUBC && 
        v[i] != FSR_SUBP && 
        v[i] != FSR_DOMAIN && 
        v[i] != FSR_NONE && 
        v[i] != FSR_RANGE)
        return FSR_ERROR_FLAG;
    }
    int flag = 0; 
    if (memchr(v,FSR_NONE,strlen(v)))
        return FSR_NONE_FLAG;
    flag |= memchr(v,FSR_SUBC,strlen(v)) ? FSR_SUBC_FLAG : FSR_NULL_FLAG; 
    flag |= memchr(v,FSR_SUBP,strlen(v)) ? FSR_SUBP_FLAG : FSR_NULL_FLAG; 
    flag |= memchr(v,FSR_DOMAIN,strlen(v)) ? FSR_DOMAIN_FLAG : FSR_NULL_FLAG; 
    flag |= memchr(v,FSR_RANGE,strlen(v)) ? FSR_RANGE_FLAG : FSR_NULL_FLAG; 
   
    return flag;
}

gchar *fsr_reasoning_level_string(int flag) {
    return g_strdup_printf(
        "%s %s %s %s %s",
        FSR_DO_NONE(flag) ? "None":"",
        FSR_DO_SC(flag) ? "rdfs:subClassOf":"",
        FSR_DO_SP(flag) ? "rdfs:subPropertyOf":"",
        FSR_DO_DOM(flag) ? "rdfs:domain":"",
        FSR_DO_RAN(flag) ? "rdfs:range":"");
}

void print_binding(fs_rid_vector **b,int cols) {
    if (!b) {
		fs_error(LOG_ERR,"vector empty");
 	 } else {
		int length = b[0]->length;
		printf("vector [%i]\n",length);
		for (int k = 0; k < length; ++k) {
		  for (int c = 0; c < cols; ++c) {
			printf("%016llX  ", b[c]->data[k]);
		  }
		  putchar('\n');
		}
	}
}


fs_rid_vector **get_stmts_by_predicate(fsp_link *link,fs_rid pred) {

    fs_rid_vector **result = NULL;

	int flags = 0 | FS_BIND_DISTINCT | FS_BIND_SUBJECT | FS_BIND_OBJECT | 
                    FS_BIND_BY_SUBJECT;
	int ans = 0;

	fs_rid_vector *prids = fs_rid_vector_new(0);
	fs_rid_vector_append(prids, pred);
	fs_rid_vector *empty_v = fs_rid_vector_new(0);
    
	ans = fsp_bind_limit_all(link, flags, empty_v, empty_v, prids, empty_v, &result, -1, -1, 0);

	return result;
}

fs_rid_vector **rdfs_subclass_stmts(fsp_link *link) {
	return get_stmts_by_predicate(link,RDFS_SUBCLASS_RID);
}

fs_rid_vector **rdfs_subproperty_stmts(fsp_link *link) {
	return get_stmts_by_predicate(link,RDFS_SUBPROPERTY_RID);
}

fs_rid_vector **rdfs_range_stmts(fsp_link *link) {
	return get_stmts_by_predicate(link,RDFS_RANGE_RID);
}

fs_rid_vector **rdfs_domain_stmts(fsp_link *link) {
	return get_stmts_by_predicate(link,RDFS_DOMAIN_RID);
}

static void free_double_fs_rid_vector(fs_rid_vector **v) {
    if (v) {
        fs_rid_vector_free(v[0]);
        fs_rid_vector_free(v[1]);
    }
}

reasoner_cache *fsr_load_reasoner_cache(fsp_link *link) {
    
    if (fsr_cache.subClassOf_msg) free(fsr_cache.subClassOf_msg);
    free_double_fs_rid_vector(fsr_cache.subClassOf_bind);
    fsr_cache.subClassOf_bind = rdfs_subclass_stmts(link);
    fsr_cache.subClassOf_msg = fsr_mtrx_to_msg(RS_GBL_SUBCLASS,fsr_cache.subClassOf_bind,2); 

    if (fsr_cache.subProperty_msg) free(fsr_cache.subProperty_msg);
    free_double_fs_rid_vector(fsr_cache.subProperty_bind);
    fsr_cache.subProperty_bind = rdfs_subproperty_stmts(link);
    fsr_cache.subProperty_msg = fsr_mtrx_to_msg(RS_GBL_SUBPROPERTY,fsr_cache.subProperty_bind,2); 

    if (fsr_cache.range_msg) free(fsr_cache.range_msg);
    free_double_fs_rid_vector(fsr_cache.range_bind);
    fsr_cache.range_bind = rdfs_range_stmts(link);
    fsr_cache.range_msg = fsr_mtrx_to_msg(RS_GBL_RANGE,fsr_cache.range_bind,2); 

    if (fsr_cache.domain_msg) free(fsr_cache.domain_msg);
    free_double_fs_rid_vector(fsr_cache.domain_bind);
    fsr_cache.domain_bind = rdfs_domain_stmts(link);
    fsr_cache.domain_msg = fsr_mtrx_to_msg(RS_GBL_DOMAIN,fsr_cache.domain_bind,2); 
   
    /*
    fs_error(LOG_ERR,"fsr_cache warmed up [%i subClassOf(s)][%i subPropertyOf(s)][%i domain(s)][%i range(s)]",
    fsr_cache.subClassOf_bind[0]->length,fsr_cache.subProperty_bind[0]->length,
    fsr_cache.domain_bind[0]->length,fsr_cache.range_bind[0]->length);
    */
    return &fsr_cache;
}


reasoner_cache *fsr_get_reasoner_cache() {
    return &fsr_cache;
}



int fsr_init_reasoner (fsp_link* link)
{
  reasoner_cache *rc = fsr_load_reasoner_cache(link);
  fsr_send_cache_to_segments(link,rc->subClassOf_msg);
  fsr_send_cache_to_segments(link,rc->subProperty_msg);
  fsr_send_cache_to_segments(link,rc->domain_msg);
  fsr_send_cache_to_segments(link,rc->range_msg);
  return 0;
}
