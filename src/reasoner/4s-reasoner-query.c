
#include "common/4s-internals.h"

#include "common/datatypes.h"
#include "common/params.h"
#include "common/error.h"
#include "4s-reasoner-common.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

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
                    FS_BIND_BY_SUBJECT | REASONER_BIND_OP;
	int ans = 0;

	fs_rid_vector *prids = fs_rid_vector_new(0);
	fs_rid_vector_append(prids, pred);
	fs_rid_vector *empty_v = fs_rid_vector_new(0);
    
	ans = fsp_bind_limit_all(link, flags, empty_v, empty_v, prids, empty_v, &result, -1, -1);

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
