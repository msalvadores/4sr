/*
    4store - a clustered RDF storage and query engine

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Copyright (C) 2006 Steve Harris for Garlik
 */

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <fcntl.h>
#include <errno.h>

#include "../common/timing.h"
#include "../common/datatypes.h"
#include "../common/error.h"
#include "../common/hash.h"
#include "tlist.h"
#include "backend.h"
#include "backend-intl.h"
#include "query-backend.h"

#include "reasoner/4s-reasoner-backend.h"
#include "reasoner/4s-reasoner-common.h"

#define TMP_SIZE 512

/* #define DEBUG_BRANCH 1 */

GHashTable* get_subject_pred(fs_backend *be,GHashTable *domains,GHashTable *ranges);
void fs_quad_print_resolved(fs_backend *be, fs_rid *quad, int flags, FILE *out);

static int slot_bits[4] = {
    FS_BIND_MODEL,
    FS_BIND_SUBJECT,
    FS_BIND_PREDICATE,
    FS_BIND_OBJECT
};

static fs_ptree_it *fs_backend_get_matches(fs_backend *be, fs_rid quad[4], int flags)
{
    fs_ptree *pt = NULL;
    fs_rid pk;
    fs_rid pair[2];

    if (flags & FS_BIND_BY_SUBJECT) {
	pt = fs_backend_get_ptree(be, quad[2], 0);
	pk = quad[1];
	pair[0] = quad[0];
	pair[1] = quad[3];
    } else {
	pt = fs_backend_get_ptree(be, quad[2], 1);
	pk = quad[3];
	pair[0] = quad[0];
	pair[1] = quad[1];
    }

    if (!pt) return NULL;

    return fs_ptree_search(pt, pk, pair);
}

static int graph_ok(const fs_rid ref[4], int flags)
{
    /* the flag means the we SHOULDN'T bind triples that are in the default
     * graph */
    if (flags & FS_QUERY_DEFAULT_GRAPH && ref[0] == FS_DEFAULT_GRAPH_RID) {
	return 0;
    }

    return 1;
}

static int bind_same(const fs_rid ref[4], int flags)
{
    int match = 1;
    switch (flags & FS_BIND_SAME_MASK) {
    case FS_BIND_SAME_XXXX:
	break;
    case FS_BIND_SAME_XXAA:
	match = (ref[2] == ref[3]);
	break;
    case FS_BIND_SAME_XAXA:
	match = (ref[1] == ref[3]);
	break;
    case FS_BIND_SAME_XAAX:
	match = (ref[1] == ref[2]);
	break;
    case FS_BIND_SAME_XAAA:
	match = (ref[1] == ref[2] && ref[2] == ref[3]);
	break;
    case FS_BIND_SAME_AXXA:
	match = (ref[0] == ref[3]);
	break;
    case FS_BIND_SAME_AXAX:
	match = (ref[0] == ref[2]);
	break;
    case FS_BIND_SAME_AXAA:
	match = (ref[0] == ref[2] && ref[2] == ref[3]);
	break;
    case FS_BIND_SAME_AAXX:
	match = (ref[0] == ref[1]);
	break;
    case FS_BIND_SAME_AAXA:
	match = (ref[0] == ref[1] && ref[1] == ref[3]);
	break;
    case FS_BIND_SAME_AAAX:
	match = (ref[0] == ref[1] && ref[1] == ref[2]);
	break;
    case FS_BIND_SAME_AAAA:
	match = (ref[0] == ref[1] && ref[1] == ref[2] &&
		 ref[2] == ref[3]);
	break;
    case FS_BIND_SAME_AABB:
	match = (ref[0] == ref[1] && ref[2] == ref[3]);
	break;
    case FS_BIND_SAME_ABAB:
	match = (ref[0] == ref[2] && ref[1] == ref[3]);
	break;
    case FS_BIND_SAME_ABBA:
	match = (ref[0] == ref[3] && ref[1] == ref[2]);
	break;
    default:
	fs_error(LOG_ERR, "unhandled BIND_SAME value");
    }

    return match;
}

int pred_is_rdfs(fs_rid pred) {
    return pred == RDF_TYPE_RID || pred == RDFS_SUBCLASS_RID || pred == RDFS_SUBPROPERTY_RID ||
           pred == RDFS_DOMAIN_RID || pred == RDFS_RANGE_RID;
}

static void bind_results(const fs_rid quad[4], int tobind, fs_rid_vector **ret)
{
    int col=0;
    if (tobind & FS_BIND_MODEL) {
	fs_rid_vector_append(ret[col++], quad[0]);
    }
    if (tobind & FS_BIND_SUBJECT) {
	fs_rid_vector_append(ret[col++], quad[1]);
    }
    if (tobind & FS_BIND_PREDICATE) {
	fs_rid_vector_append(ret[col++], quad[2]);
    }
    if (tobind & FS_BIND_OBJECT) {
	fs_rid_vector_append(ret[col++], quad[3]);
    }
}

fs_rid_vector **fs_bind(fs_backend *be, fs_segment segment, unsigned int tobind,
			     fs_rid_vector *mv, fs_rid_vector *sv,
			     fs_rid_vector *pv, fs_rid_vector *ov,
                             int offset, int limit)
{
    if (!(tobind & (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT))) {
	fs_error(LOG_ERR, "tried to bind without s/o spec");

	return NULL;
    } else if ((tobind & (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT)) ==
	       (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT)) {
	fs_error(LOG_ERR, "tried to bind with s+o spec set");

	return NULL;
    }

    int reasoner_bind = (tobind & REASONER_BIND_OP);
    int do_rdfs = !reasoner_bind && be->reasoner;
    #ifdef DEBUG_RDFS
     fs_error(LOG_ERR, "segment %i do_rdfs[%d] reasoner_bind[%d] be->reasoner[%p]",segment,do_rdfs,reasoner_bind,be->reasoner);
    #endif
    double then = fs_time();

    limit = (limit == -1) ? INT_MAX : limit;
    offset = (offset == -1) ? 0 : offset;

    int cols = 0;
    for (int i=0; i<4; i++) {
	if (tobind & slot_bits[i]) {
	    cols++;
	}
    }

    fs_rid_vector_sort(mv);
    fs_rid_vector_uniq(mv, 0);
    fs_rid_vector_sort(sv);
    fs_rid_vector_uniq(sv, 0);
    fs_rid_vector_sort(pv);
    fs_rid_vector_uniq(pv, 0);
    fs_rid_vector_sort(ov);
    fs_rid_vector_uniq(ov, 0);
    
    fs_rid_vector **ret;
    if (cols == 0) {
	ret = calloc(1, sizeof(fs_rid_vector *));
	limit = 1;
    } else {
	ret = calloc(cols, sizeof(fs_rid_vector *));
    }

    const int mvl = fs_rid_vector_length(mv);
    //if (mvl > 0 && !fs_rid_vector_contains(mv,ENTAIL_GRAPH)) {
    if (mvl > 0 && !fs_rid_vector_contains(mv,ENTAIL_GRAPH) && !(tobind & FS_BIND_MODEL)) {
        do_rdfs= 0;
        #ifdef DEBUG_RDFS
        fs_error(LOG_ERR, "segment %i do_rdfs=0 mvl>0 and ENTAIL_GRAPH not in mv",segment);
        fs_error(LOG_ERR, "model graph ====> %llx",mv->data[0]);
        #endif
    }
    const int svl = fs_rid_vector_length(sv);
    int pvl = fs_rid_vector_length(pv);
    const int ovl = fs_rid_vector_length(ov);

    /* if the query looks like (?m _ _ _) we can consult the model hash */
    if (cols == 1 && tobind & FS_BIND_MODEL && tobind &&
        tobind & FS_BIND_DISTINCT &&
        mvl == 0 && svl == 0 && pvl == 0 && ovl == 0) {
	ret[0] = fs_mhash_get_keys(be->models);

	be->out_time[segment].bind_count++;
	be->out_time[segment].bind += fs_time() - then;

	return ret;
    }

    /* if the query looks like (_ _ ?p _) we can consult the predicate list */
    if (cols == 1 && tobind & FS_BIND_PREDICATE && tobind & FS_BIND_DISTINCT &&
        mvl == 0 && svl == 0 && pvl == 0 && ovl == 0) {
	int length = limit < be->ptree_length ? limit : be->ptree_length;
	ret[0] = fs_rid_vector_new(length);
	int outpos = 0;
	for (int i=0; i<length; i++) {
	    fs_backend_ptree_limited_open(be, i);
	    if (fs_ptree_count(be->ptrees_priv[i].ptree_s) > 0) {
		ret[0]->data[outpos++] = be->ptrees_priv[i].pred;
	    }
	}
	ret[0]->length = outpos;

	be->out_time[segment].bind_count++;
	be->out_time[segment].bind += fs_time() - then;

	return ret;
    }

    for (int i=0; i<cols; i++) {
	ret[i] = fs_rid_vector_new(0);
    }
    int count = 0;

    /* if the query looks like DISINTCT (_ _ p ?o) we can use a set to get a
     * cheap DISTINCT */
    if (cols == 1 && ((tobind & (FS_BIND_MODEL | FS_BIND_SUBJECT | 
	FS_BIND_PREDICATE | FS_BIND_OBJECT)) == FS_BIND_OBJECT) && tobind &
	FS_BIND_DISTINCT && mvl == 0 && svl == 0 && pvl == 1 && ovl == 0) {
	fs_ptree *pt = fs_backend_get_ptree(be, pv->data[0], 0);
	if (pt) {
	    fs_rid_set *set = fs_rid_set_new();
	    fs_rid quad[4] = { FS_RID_NULL, FS_RID_NULL, pv->data[0],
			       FS_RID_NULL };
	    fs_ptree_it *it = fs_ptree_traverse(pt, FS_RID_NULL);
	    while (it && fs_ptree_traverse_next(it, quad) && count<limit) {
		if (!bind_same(quad, tobind)) continue;
		if (!graph_ok(quad, tobind)) continue;
		count++;
		fs_rid_set_add(set, quad[3]);
	    }
	    fs_ptree_it_free(it);
	    fs_rid_vector_append_set(ret[0], set);
	}

	be->out_time[segment].bind_count++;
	be->out_time[segment].bind += fs_time() - then;

	return ret;
    }

    /* if the query looks like (m ?s/_ ?p/_ ?o/_) we can consult the model
     * index */
    if (!do_rdfs || !fs_rid_vector_contains(mv,ENTAIL_GRAPH)) {
    if (mvl > 0 && svl == 0 && pvl == 0 && ovl == 0) {
	for (int i=0; i<mvl; i++) {
	    const fs_rid model = mv->data[i];
	    fs_index_node mnode;
	    fs_mhash_get(be->models, model, &mnode);
	    /* that model is not in the store */
	    if (mnode == 0) {
		continue;
	    /* it's stored in a model index file */
	    } else if (mnode == 1) {
		fs_tlist *tl = fs_tlist_open(be, model, O_RDONLY);
		if (!tl) continue;
		fs_rid triple[3];
		fs_tlist_rewind(tl);
		while (fs_tlist_next_value(tl, triple) && count < limit) {
		    const fs_rid quad[4] =
				    { model, triple[0], triple[1], triple[2] };
		    if (!bind_same(quad, tobind)) continue;
		    if (!graph_ok(quad, tobind)) continue;
		    bind_results(quad, tobind, ret);
		    count++;
		}
		fs_tlist_close(tl);
	    /* it's stored in the model table */
	    } else {
		fs_tbchain_it *it =
		    fs_tbchain_new_iterator(be->model_list, model, mnode);
		fs_rid triple[3];
		while (fs_tbchain_it_next(it, triple) && count < limit) {
		    const fs_rid quad[4] =
				    { model, triple[0], triple[1], triple[2] };
		    if (!bind_same(quad, tobind)) continue;
		    if (!graph_ok(quad, tobind)) continue;
		    bind_results(quad, tobind, ret);
		    count++;
		}
		fs_tbchain_it_free(it);
            }
	}

	be->out_time[segment].bind_count++;
	be->out_time[segment].bind += fs_time() - then;

	return ret;
    }
    }

    int nloops = -1;
    int by_subject = tobind & FS_BIND_BY_SUBJECT;
    const int io = by_subject ? 2 : 0; //whereis ov
    fs_rid_vector **looper = NULL;
    if (by_subject && svl == 0) {
        nloops=1;
    } else {
        nloops=3;
        looper = calloc(3, sizeof(fs_rid_vector *));
        looper[1] = mv;
        if (by_subject) {
            looper[0] = sv;
            looper[2] = ov;
        } else {
            looper[0] = ov;
            looper[2] = sv;
        }
    }

   int tree_object_flag = by_subject ? 0 : 1;
   int i_ext=0;   
    #ifdef DEBUG_RDFS
    fs_error(LOG_ERR, "segment %i do_rdfs %i nloops %i reasoner_bind %i reasoner_conf %p",
                       segment,do_rdfs,nloops,reasoner_bind,be->reasoner);
    fprintf(stderr,"mv:");
    fs_rid_vector_print_resolved(be,mv,0,stdout);  
    fprintf(stderr,"sv:");
    fs_rid_vector_print_resolved(be,sv,0,stdout);  
    fprintf(stderr,"pv:");
    fs_rid_vector_print_resolved(be,pv,0,stdout);  
    fprintf(stderr,"ov:");
    fs_rid_vector_print_resolved(be,ov,0,stdout);  
    #endif
   fs_rid_vector *pre_preds = NULL;
   if (do_rdfs && pvl != 0) { //if predicates then extend the predicates with subProp closure
        fs_rid_vector *extended_predicates = rdfs_subproperties_vector(be->reasoner,pv);
        pre_preds = pv;
        pv = extended_predicates;
        #ifdef DEBUG_RDFS
        fs_error(LOG_ERR, "segment %i rdfs predicates extended %i->%i",segment,pvl,fs_rid_vector_length(pv));
        fs_rid_vector_print_resolved(be,pv,0,stdout);  
        #endif
        pvl = fs_rid_vector_length(pv);
   }
   const int pi = pvl ? pvl : be->ptree_length;
   fs_rid_vector *extended_objects = NULL;
   fs_rid_vector *pre_objects = NULL;


   int do_rd = 0;
   #ifdef FS_RDFS_DOMRAN
   do_rd = 1;
   #endif

   GHashTable* preds_by_sub = NULL;

   int domain_done = 0;
   GList *entailments = NULL;

   for (int p=0; p<pi && count<limit; p++) {
       if (!pvl) fs_backend_ptree_limited_open(be,p);
       fs_ptree *pt = pvl ? fs_backend_get_ptree(be, pv->data[p], tree_object_flag) : 
       (tobind & FS_BIND_BY_SUBJECT ? be->ptrees_priv[p].ptree_s : be->ptrees_priv[p].ptree_o );
       fs_rid pred = pvl ? pv->data[p] : be->ptrees_priv[p].pred;

       if (!pt) continue; 
       
       if (do_rdfs && do_rd && !domain_done) { //rdf:type domain should be inferred only once.
            if (pred == RDF_TYPE_RID || !pvl) { // if no P then we have to run it either way to expand ?p
            domain_done = 1;
            if (preds_by_sub==NULL)
                preds_by_sub = get_subject_pred(be,get_rdfs_domains(be->reasoner),get_rdfs_ranges(be->reasoner));
            if (preds_by_sub) {
                i_ext = rdfs_extend_quads_domain(be->reasoner,preds_by_sub,
                                                svl ? sv : NULL,ovl ? ov : NULL,&entailments,tobind,&count);
                #ifdef DEBUG_RDFS
                    fs_error(LOG_ERR, "segment %i rdfs domain %i triples ",segment,i_ext);
                #endif
            }
            }
       }

       if (do_rdfs && ovl != 0) {
           if (pred_is_rdfs(pred)) { 
                if (!extended_objects) {
                    extended_objects = rdfs_sub_classes_vector(be->reasoner,ov);
                    pre_objects = ov;
                    #ifdef DEBUG_RDFS
                    fs_error(LOG_ERR, "segment %i objects extended  %i->%i",
                                segment,ovl,fs_rid_vector_length(extended_objects));
                    #endif
                }
                looper[io] = extended_objects;
                //fs_rid_vector_print_resolved(be,looper[io],0,stdout);  
           } else
                looper[io] = ov;
       }
       
       int entail_graph_request=0;
       if (nloops == 1) { //1 loop, always MV, always quad selector and never pair search
           fs_rid_vector *index=mv;
           int i0 = fs_rid_vector_length(index);
           i0 = i0 ? i0 : 1;
           for (int j0=0; j0 < i0 && count<limit ;j0++ ) {
		        fs_rid quad[4] = { FS_RID_NULL, 
                                   FS_RID_NULL,
                                   pred , 
                                   FS_RID_NULL };
                fs_rid mrid = mvl ? index->data[j0] : FS_RID_NULL;
                entail_graph_request = mrid == ENTAIL_GRAPH ? 1 : 0;
                if (entail_graph_request)
                    mrid = FS_RID_NULL;
                fs_ptree_it *it = fs_ptree_traverse(pt, mrid);
                while (it && fs_ptree_traverse_next(it, quad) && count<limit) {
                    if (!bind_same(quad, tobind)) continue;
                    if (!graph_ok(quad, tobind)) continue;
                    if (do_rdfs && ( 
                         (pred_is_rdfs(pred) && ovl == 0) || pvl == 0) ) {
                        i_ext = rdfs_extend_quads(be->reasoner,quad,&entailments,tobind,limit,&count);
                        #ifdef DEBUG_RDFS
                        fs_error(LOG_ERR, "segment %i rdfs extend %i triples ",segment,i_ext);
                        #endif
                    }
                    //fs_quad_print_resolved(be,quad,0,stderr);
                    if ((pre_preds && !fs_rid_vector_contains(pre_preds,quad[2])) ||
                        (pre_objects && !fs_rid_vector_contains(pre_objects,quad[3]))) { 
                            quad[0]=ENTAIL_GRAPH;
                            fs_rid *cpy_quad = get_new_quad_for(quad[0],quad[1],quad[2],quad[3]);
                            if (controlled_append(&entailments,cpy_quad)) {
                                count++;
                             }
                    }
                    else if (!entail_graph_request) {
                        count++;
                        bind_results(quad, tobind, ret);
                    }

                }
                fs_ptree_it_free(it);
           }
       } else { //3 loops  always pair serch

           int i0 = fs_rid_vector_length(looper[0]);
           int z1 = fs_rid_vector_length(looper[1]); //looper 1 is MV always
           int i1 = z1 ? z1 : 1;
           int z2 = fs_rid_vector_length(looper[2]);
           int i2 = z2 ? z2 : 1;

           for (int j0=0; j0 < i0 && count<limit ;j0++ ) {
               fs_rid pk = looper[0]->data[j0];
               for (int j1=0; j1 < i1 && count<limit ;j1++ ) {
               for (int j2=0; j2 < i2 && count<limit ;j2++ ) {
                    fs_rid pair[2] = { FS_RID_NULL, FS_RID_NULL };
                    if (z1) pair[0] = looper[1]->data[j1];
                    if (z2) pair[1] = looper[2]->data[j2];
                    entail_graph_request = pair[0] == ENTAIL_GRAPH ? 1 : 0;
                    fs_ptree_it *it = fs_ptree_search(pt, pk, pair);
                    while (it && fs_ptree_it_next(it, pair) && count<limit) {
                        fs_rid quad_s = by_subject ? pk : pair[1];
                        fs_rid quad_o = by_subject ? pair[1] : pk;
                        fs_rid quad[4] = {pair[0],quad_s,pred,quad_o};
                        if (!bind_same(quad, tobind)) continue;
                        if (!graph_ok(quad, tobind)) continue;
                        if (do_rdfs && ( ( pred_is_rdfs(pred) && ovl == 0) || pvl == 0) ) {
                            i_ext = rdfs_extend_quads(be->reasoner,quad,&entailments,tobind,limit,&count);
                            #ifdef DEBUG_RDFS
                            fs_error(LOG_ERR, "segment %i rdfs extend %i triples ",segment,i_ext);
                            #endif
                        }
                        //fs_quad_print_resolved(be,quad,0,stderr);
                        if ((pre_preds && !fs_rid_vector_contains(pre_preds,quad[2])) ||
                            (pre_objects && !fs_rid_vector_contains(pre_objects,quad[3]))) { 
                                quad[0]=ENTAIL_GRAPH;
                                fs_rid *cpy_quad = get_new_quad_for(quad[0],quad[1],quad[2],quad[3]);
                                if (controlled_append(&entailments,cpy_quad)) {
                                    count++;
                                 }
                        }
                        else if (!entail_graph_request) {
                            count++;
                            bind_results(quad, tobind, ret);
                        }


                    }
                    fs_ptree_it_free(it);
               }
               }
           }
       }
   }
   #ifdef DEBUG_RDFS
   fs_error(LOG_ERR, "segment-->%i count-->%i entailments-->%i",segment,count, g_list_length(entailments));
   #endif
   if (do_rdfs && g_list_length(entailments) > 0) {
        entailments = get_equads_assignment(segment,entailments,be->reasoner);
   }
   while(entailments) {
        fs_rid *q = (fs_rid *) entailments->data;
        #ifdef DEBUG_RDFS
        fs_error(LOG_ERR, "adding entailment %llx %llx %llx %llx",q[0],q[1],q[2],q[3]);
        #endif
        if (!bind_same(q, tobind)) continue;
        if (!graph_ok(q, tobind)) continue;
        bind_results(q, tobind, ret);
        entailments=g_list_next(entailments);
   }
   if (entailments) 
       g_list_free(entailments);
   if (looper)
       free(looper);
    TIME("bind");

    be->out_time[segment].bind_count++;
    be->out_time[segment].bind += fs_time() - then;

    /* if there are no results (as opposed to no bindings, then we need to
     * signal that */
    if (count == 0 && cols == 0) {
	/* FIXME there may be a leak here, but it only happens under error
         * conditions */
	return NULL;
    }
    #if 0
    for (int z=0;z<cols;z++) {
        fprintf(stderr,"col(%i):",z);
        fs_rid_vector_print_resolved(be,ret[z],0,stdout);  
    }
    #endif
    return ret;
}

/* WARNING: this has completly different semantics to fs_bind,
   () () (:x :y) ("foo" "bar") means find common subjects like
   ?x :x "foo" . ?y :y "bar", only m and s slots are disjunctive */
fs_rid_vector **fs_reverse_bind(fs_backend *be, fs_segment segment,
			       unsigned int tobind,
			       fs_rid_vector *mvi, fs_rid_vector *svi,
			       fs_rid_vector *pv, fs_rid_vector *ov,
                               int offset, int limit)
{

    if (!(tobind & (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT))) {
	fs_error(LOG_ERR, "tried to reverse_bind without s/o spec");

	return NULL;
    } else if ((tobind & (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT)) ==
	       (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT)) {
	fs_error(LOG_ERR, "tried to reverse_bind with s+o spec set");

	return NULL;
    } else if (tobind & FS_BIND_BY_OBJECT) {
	fs_error(LOG_ERR, "tried to reverse bind by object");

	return NULL;
    }
    double then = fs_time();

    limit = (limit == -1) ? INT_MAX : limit;

    int cols = 0;
    for (int i=0; i<4; i++) {
	if (tobind & slot_bits[i]) {
	    cols++;
	}
    }

    fs_rid_vector *mv = NULL, *sv = NULL;
    if (mvi->length) mv = fs_rid_vector_copy(mvi);
    if (svi->length) sv = fs_rid_vector_copy(svi);

    int iters = ov->length;
    if (pv->length && pv->length != iters) {
	fs_error(LOG_ERR, "tried to reverse bind with length(p) != length(o)");

	return NULL;
    }
    fs_rid_vector **ret;
    if (cols == 0) {
	ret = calloc(1, sizeof(fs_rid_vector *));
    } else {
	ret = calloc(cols, sizeof(fs_rid_vector *));
    }

    fs_rid quad[4] = { FS_RID_NULL, FS_RID_NULL, FS_RID_NULL, FS_RID_NULL };

    fs_ptree_it *res_unsorted[iters];
    fs_ptree_it *res[iters];
    for (int i=0; i<iters; i++) {
	if (pv->length) {
	    quad[2] = pv->data[i];
	}
	if (ov->length) {
	    quad[3] = ov->data[i];
	}
	res_unsorted[i] = fs_backend_get_matches(be, quad, tobind & FS_BIND_SAME_MASK);
    }
    for (int i=0; i<iters; i++) {
	int narrowest = 0;
	int narrowest_size = INT_MAX;
	for (int j=0; j<iters; j++) {
	    if (!res_unsorted[j]) continue;
	    if (fs_ptree_it_get_length(res_unsorted[j]) < narrowest_size) {
		narrowest = j;
		narrowest_size = fs_ptree_it_get_length(res_unsorted[j]);
	    }
	}
	res[i] = res_unsorted[narrowest];
	res_unsorted[narrowest] = NULL;
    }

    fs_rid lpair[2];
    fs_rid_vector *inter[2];
    for (int s=0; s<2; s++) {
	inter[s] = fs_rid_vector_new(0);
    }
    for (int i=0; i<iters; i++) {
	while (res[i] && fs_ptree_it_next(res[i], lpair)) {
	    int match = 1;
	    if (mv && !fs_rid_vector_contains(mv, lpair[0])) match = 0;
	    if (match && sv && !fs_rid_vector_contains(sv, lpair[1])) match = 0;
	    if (match) {
		if (tobind & FS_BIND_MODEL) {
		    fs_rid_vector_append(inter[0], lpair[1]);
		}
		if (tobind & FS_BIND_SUBJECT) {
		    fs_rid_vector_append(inter[1], lpair[1]);
		}
	    }
	}
	fs_ptree_it_free(res[i]);
	if (tobind & FS_BIND_MODEL) {
	    if (mv) {
		fs_rid_vector_free(mv);
	    }
	    mv = fs_rid_vector_copy(inter[0]);
	    fs_rid_vector_free(inter[0]);
	    inter[0] = fs_rid_vector_new(0);
	}
	if (tobind & FS_BIND_SUBJECT) {
	    if (sv) {
		fs_rid_vector_free(sv);
	    }
	    sv = fs_rid_vector_copy(inter[1]);
	    fs_rid_vector_free(inter[1]);
	    inter[1] = fs_rid_vector_new(0);
	}
    }

    /* If we just need to bind subjects then we can use the intersection */
    if (cols == 1 && tobind & FS_BIND_SUBJECT) {
	fs_rid_vector_truncate(sv, limit);
	ret[0] = sv;
	fs_rid_vector_free(inter[0]);
	fs_rid_vector_free(inter[1]);
	be->out_time[segment].bind_count++;
	be->out_time[segment].bind += fs_time() - then;

	return ret;
    }

    if (cols == 2 && tobind & FS_BIND_SUBJECT && tobind & FS_BIND_MODEL) {
	fs_rid_vector_truncate(mv, limit);
	fs_rid_vector_truncate(sv, limit);
	ret[0] = mv;
	ret[1] = sv;
	fs_rid_vector_free(inter[0]);
	fs_rid_vector_free(inter[1]);
	be->out_time[segment].bind_count++;
	be->out_time[segment].bind += fs_time() - then;

	return ret;
    }

    fs_error(LOG_CRIT, "tried to reverse bind, requesting unsupported slots, "
	     "cols: %d, flags: %08x, [%p, %p]", cols, tobind, inter[0], inter[1]);
    
    fs_rid_vector_free(inter[0]);
    fs_rid_vector_free(inter[1]);

    be->out_time[segment].bind_count++;
    be->out_time[segment].bind += fs_time() - then;

    return ret;
}

fs_rid_vector **fs_bind_first(fs_backend *be, fs_segment segment,
                              unsigned int tobind,
			      fs_rid_vector *mv, fs_rid_vector *sv,
			      fs_rid_vector *pv, fs_rid_vector *ov,
                              int count)
{
    if (!(tobind & (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT))) {
	fs_error(LOG_ERR, "tried to bind without s/o spec");

	return NULL;
    } else if ((tobind & (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT)) ==
	       (FS_BIND_BY_SUBJECT | FS_BIND_BY_OBJECT)) {
	fs_error(LOG_ERR, "tried to bind with s+o spec set");

	return NULL;
    }
    double then = fs_time();

    int cols = 0;
    for (int i=0; i<4; i++) {
	if (tobind & slot_bits[i]) {
	    cols++;
	}
    }

    /* streaming binds aren't implemented in this branch yet */
    fs_error(LOG_ERR, "not implemented");
    return NULL;

    fs_rid_vector **ret;
    if (cols == 0) {
	ret = calloc(1, sizeof(fs_rid_vector *));
    } else {
	ret = calloc(cols, sizeof(fs_rid_vector *));
    }
    for (int i=0; i<cols; i++) {
	ret[i] = fs_rid_vector_new(0);
    }

    if (be->stream) {
	fs_error(LOG_ERR, "bind_first(%d) while already streaming", segment);
	return NULL;
    }

    /* TODO bind streaming quad pattern */

    be->out_time[segment].bind_count++;
    be->out_time[segment].bind += fs_time() - then;

    if (cols == 0) {
	free(ret);
	return NULL;
    }

    return ret;
}

fs_rid_vector **fs_bind_next(fs_backend *be, fs_segment segment,
                             unsigned int tobind, int count)
{
    if (!be->stream) {
        fs_error(LOG_ERR, "bind_next(%d) while not streaming", segment);
        return NULL;
    }

    double then = fs_time();

    int cols = 0;
    for (int i=0; i<4; i++) {
        if (tobind & slot_bits[i]) {
            cols++;
        }
    }

    fs_rid_vector **ret;
    if (cols == 0) {
        ret = calloc(1, sizeof(fs_rid_vector *));
    } else {
        ret = calloc(cols, sizeof(fs_rid_vector *));
    }
    for (int i=0; i<cols; i++) {
        ret[i] = fs_rid_vector_new(0);
    }

    /* TODO bind streaming quad pattern */

    be->out_time[segment].bind_count++;
    be->out_time[segment].bind += fs_time() - then;

    if (cols == 0) {
        free(ret);
        return NULL;
    }

    return ret;
}

int fs_bind_done(fs_backend *be, fs_segment segment)
{
    if (be->stream) {
	/* TODO cleanup */

        return 0;
    } else {
        fs_error(LOG_ERR, "bind_done(%d) while not streaming", segment);
        return 1;
    }
}

unsigned long long int fs_bind_price(fs_backend *be, fs_segment segment,
			     unsigned int tobind,
			     fs_rid_vector *mv, fs_rid_vector *sv,
			     fs_rid_vector *pv, fs_rid_vector *ov)
{
    /* NB this isn't implemented in this branch */

    return 0;
}

int fs_resolve(fs_backend *be, fs_segment segment, fs_rid_vector *v,
	fs_resource *out)
{
    double then = fs_time();
    int ret = 0;

    for (int i=0; i<v->length; i++) {
	out[i].rid = v->data[i];
    }
    ret = fs_rhash_get_multi(be->res, out, v->length);

    be->out_time[segment].resolve_count++;
    be->out_time[segment].resolve += fs_time() - then;

    return ret;
}

int fs_resolve_rid(fs_backend *be, fs_segment segment, fs_rid rid, fs_resource *out)
{
    out->rid = rid;
    out->attr = FS_RID_NULL;

    if (FS_IS_BNODE(rid)) {
	out->lex =  g_strdup_printf("_:b%llx", rid);

	return 0;
    }

    return fs_rhash_get(be->res, out);
}

void fs_quad_print_resolved(fs_backend *be, fs_rid *quad, int flags, FILE *out) {
	fs_resource res[4];
    for(int q=0;q<4;q++) {
        fs_resolve_rid(be, quad[q] & 0x7, quad[q], &res[q]);
        if (FS_IS_BNODE(quad[q])) {
            fprintf(out, "<%s> ", res[q].lex);
        } else if (FS_IS_URI(quad[q])) {
            fprintf(out, "<%s> ",res[q].lex);
        } else if (FS_IS_LITERAL(quad[q])) {
            fprintf(out, "\"%s\"",res[q].lex);
        } else {
            fprintf(out, "%4d %llx ?%s?\n",q,quad[q], res[q].lex);
        }
    }
    fprintf(out, "\n");
}

void fs_rid_vector_print_resolved(fs_backend *be, fs_rid_vector *v, int flags, FILE *out)
{
    if (!v) {
	fprintf(out, "RID vector: (null)\n");

	return;
    }
    fprintf(out, "RID vector (%d items)\n", v->length);
    for (int i=0; i<v->length; i++) {
	fs_resource res;
	fs_resolve_rid(be, v->data[i] & 0x7, v->data[i], &res);
	if (FS_IS_BNODE(v->data[i])) {
	    fprintf(out, "%4d %llx %s\n", i, v->data[i], res.lex);
	} else if (FS_IS_URI(v->data[i])) {
	    fprintf(out, "%4d %llx <%s>\n", i, v->data[i], res.lex);
	} else if (FS_IS_LITERAL(v->data[i])) {
	    fprintf(out, "%4d %llx \"%s\"\n", i, v->data[i], res.lex);
	} else {
	    fprintf(out, "%4d %llx ?%s?\n", i, v->data[i], res.lex);
	}
    }
}

fs_data_size fs_get_data_size(fs_backend *be, int seg)
{
    fs_data_size ret;

    if (!be->ptrees_priv) {
	fs_error(LOG_WARNING, "list unavailable");
	fs_data_size errret = { 0, 0, 0, 0, 0 };

	return errret;
    }
    ret.quads_s = 0;
    ret.quads_sr = 0;
    for (int i=0; i<be->ptree_length; i++) {
	fs_backend_ptree_limited_open(be, i);
	ret.quads_s += fs_ptree_count(be->ptrees_priv[i].ptree_s);
	ret.quads_sr += fs_ptree_count(be->ptrees_priv[i].ptree_o);
    }
    ret.quads_o = -1;
    ret.resources = fs_rhash_count(be->res);
    if (be->models) {
	ret.models_s = fs_mhash_count(be->models);
    } else {
	ret.models_s = -1;
    }
    ret.models_o = -1;

    return ret;
}

GHashTable* get_subject_pred(fs_backend *be,GHashTable *domains,GHashTable *ranges) {
       #ifdef DEBUG_RDFS
       fs_error(LOG_ERR, "get_subject_predi domains [%i] ranges [%i] ",g_list_length(g_hash_table_get_keys(domains)),
       g_list_length(g_hash_table_get_keys(ranges)));
       #endif
       GHashTable* lookup = g_hash_table_new( (GHashFunc) fs_rid_hash, (GEqualFunc) fs_rid_equal);
       GList *list = g_hash_table_get_keys(domains);
       fs_rid_set *dom_preds = NULL;
       fs_rid pred;
       while(list) {
           pred = *((fs_rid *) list->data);
           fs_ptree *pt = fs_backend_get_ptree(be, pred, 0);
           if (pt) {
                fs_ptree_it *it = fs_ptree_traverse(pt, FS_RID_NULL);
                dom_preds = g_hash_table_lookup(domains,&pred);
                if (dom_preds) {
                    fs_rid quad[4] = { FS_RID_NULL, 
                                   FS_RID_NULL,
                                   pred, 
                                   FS_RID_NULL };
                    while (it && fs_ptree_traverse_next(it, quad)) {
                        add_elto_set(lookup,&quad[1],dom_preds);
                    }
                }
           }
           list = g_list_next(list);
       }
       list = g_hash_table_get_keys(ranges);
       fs_rid_set *ranges_pred = NULL;
       while(list) {
           pred = *((fs_rid *) list->data);
           fs_ptree *pt = fs_backend_get_ptree(be, pred, 1);
           if (pt) {
                fs_ptree_it *it = fs_ptree_traverse(pt, FS_RID_NULL);
                ranges_pred = g_hash_table_lookup(ranges,&pred);
                if (ranges_pred) {
                    fs_rid quad[4] = { FS_RID_NULL, 
                                   FS_RID_NULL,
                                   pred, 
                                   FS_RID_NULL };
                    while (it && fs_ptree_traverse_next(it, quad)) {
                        add_elto_set(lookup,&quad[1],ranges_pred);
                    }
                }
           }
           list = g_list_next(list);
       }
       //fs_error(LOG_ERR,"subjects type inferred table");
       //dumpTable(lookup);
       return lookup;
}

/* vi:set ts=8 sts=4 sw=4: */
