
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "4s-reasoner-common.h"
#include "common/4store.h"
#include "common/error.h"
#include "backend/backend-intl.h"

typedef struct {
    fs_rid_vector *parents;
    fs_rid_vector *children;
    fs_rid rid;
} _rid_node;

static fs_rid_vector *get_tree_closure(fs_rid node,GHashTable* nodes, fs_rid_vector *partial);

static GHashTable* subClassOf_node = NULL;
static GHashTable* subPropertyOf_node = NULL;
static GHashTable* range_node = NULL;
static GHashTable* domain_node = NULL;
static class_membership_dr cache_dr;

static _rid_node* get_new_rid_node(fs_rid rid) {
    _rid_node *n = malloc(sizeof(_rid_node));
    n->parents = fs_rid_vector_new(0);
    n->children = fs_rid_vector_new(0);
    n->rid = rid;
    return n;
}

static void free_new_rid_node(_rid_node *n) {
    fs_rid_vector_free(n->parents);
    fs_rid_vector_free(n->children);
    free(n);
}

GHashTable *fsr_get_rdfs_domains() {
    return domain_node;
}

GHashTable *fsr_get_rdfs_ranges() {
    return range_node;
}

static _rid_node *get_node(GHashTable* lookup,fs_rid rid) {
	_rid_node *node = (_rid_node *) g_hash_table_lookup(lookup,&rid);
	if (node == NULL) {
		node = get_new_rid_node(rid);
        fs_rid *cpy = malloc(sizeof(fs_rid));
        *cpy = rid;
		g_hash_table_insert(lookup,cpy,node);
	}
	return node;
}

void fsr_set_class_membership_dr(GHashTable* lookup, fs_rid_vector *keys) {
    cache_dr.lookup=lookup;
    cache_dr.keys=keys;
}

class_membership_dr *fsr_get_class_membership_dr() {
    return &cache_dr;
}

void fsr_dump_table(GHashTable *table) {
    GList *tmp,*list = NULL;
    list = g_hash_table_get_keys(table);
    tmp = list;
    while(tmp) {
        fs_rid_set *d = g_hash_table_lookup(table,tmp->data);
        fs_rid r;
        while((r=fs_rid_set_next(d))!=FS_RID_NULL) {
            fs_error(LOG_ERR, "\t%llx",r);
        }
        fs_rid_set_rewind(d);
        tmp = g_list_next(tmp);
    }
}

guint fsr_add_elto_set(GHashTable* lookup,fs_rid *rid,fs_rid_vector *eltos) {
    guint res = 0;
	GArray *s = (GArray *) g_hash_table_lookup(lookup,rid);
	if (s == NULL) {
		s =  g_array_new(TRUE,TRUE,sizeof(fs_rid)); 
        fs_rid *key = calloc(1, sizeof(fs_rid));
        *key=*rid;
		g_hash_table_insert(lookup,key,s);
	}
    guint l = fs_rid_vector_length(eltos);
    for(int i=0;i<l;i++) {
        g_array_append_val(s,eltos->data[i]);
        res++;
    }
    return res;
}

gboolean fsr_rid_equal(fs_rid *v1,fs_rid *v2) {
	return *v1==*v2;
}

guint fsr_rid_hash(fs_rid *v) {
	return (guint)(*v);
}

static void cache_hash_destroy_key(gpointer k) {
    free(k);
}
static void cache_hash_destroy_val_table(gpointer v) {
    fs_rid_vector_free(v);
}
static void cache_hash_destroy_val_node(gpointer v) {
    free_new_rid_node(v);
}

static GHashTable* edges_to_tree(fs_rid_vector **edges) {
	GHashTable* node_lookup = g_hash_table_new_full( (GHashFunc) fsr_rid_hash, (GEqualFunc) fsr_rid_equal, cache_hash_destroy_key, cache_hash_destroy_val_node);

	int length = edges[0]->length;
	for (int k = 0; k < length; ++k) {
		fs_rid superElto = edges[1]->data[k];
		fs_rid subElto = edges[0]->data[k];
		_rid_node * superNode = get_node(node_lookup,superElto);
		_rid_node * subNode = get_node(node_lookup,subElto);
        if (superNode != subNode) {
            if (FS_IS_URI(subNode->rid) && !fs_rid_vector_contains(superNode->children,subNode->rid))
                fs_rid_vector_append(superNode->children,subNode->rid);
            if (FS_IS_URI(superNode->rid) && !fs_rid_vector_contains(subNode->parents,superNode->rid))
                fs_rid_vector_append(subNode->parents,superNode->rid);
        }
	}
	return node_lookup;
}


static void add_elto_table(GHashTable* lookup,fs_rid rid,fs_rid elto) {
	fs_rid_vector *s = (fs_rid_vector *) g_hash_table_lookup(lookup,&rid);
	if (s == NULL) {
		s = fs_rid_vector_new(0);
        fs_rid *cpy = malloc(sizeof(fs_rid));
        *cpy = rid;
		g_hash_table_insert(lookup,cpy,s);
	}
    if (!fs_rid_vector_contains(s,elto))
        fs_rid_vector_append(s,elto);
}

static GHashTable* edges_to_table(fs_rid_vector **edges) {
    GHashTable* node_lookup = g_hash_table_new_full( (GHashFunc) fsr_rid_hash, (GEqualFunc) fsr_rid_equal, cache_hash_destroy_key, cache_hash_destroy_val_table);

	int length = edges[0]->length;
	for (int k = 0; k < length; ++k) {
		fs_rid key = edges[0]->data[k];
		fs_rid elto = edges[1]->data[k];
        if (elto != key)
            add_elto_table(node_lookup,key,elto);
	}
	return node_lookup;
}

static void traverse(_rid_node *node,fs_rid_vector *closure,GHashTable* nodes) {
    fs_rid value = node->rid;
    if (!fs_rid_vector_contains(closure,value))
        fs_rid_vector_append(closure,value);
    if (node && node->children) {
         int nc = fs_rid_vector_length(node->children);
         for (int n=0;n<nc;n++) {
            fs_rid rid_kid = node->children->data[n];
            _rid_node *node_kid = (_rid_node *) g_hash_table_lookup(nodes,&rid_kid);
            if (node_kid && !fs_rid_vector_contains(closure,node_kid->rid))
                traverse(node_kid,closure,nodes);
         }
    }
}

static fs_rid_vector *get_tree_closure(fs_rid node,GHashTable* nodes, fs_rid_vector *partial) {
    if (!nodes) {
        fs_rid_vector *x = fs_rid_vector_new(0);
        fs_rid_vector_append(x,node);
        return x;
    }
	_rid_node *nodeTree = (_rid_node *) g_hash_table_lookup(nodes,&node);
    fs_rid_vector *closure = partial != NULL ? partial : fs_rid_vector_new(0);
    if (!fs_rid_vector_contains(closure,node))
        fs_rid_vector_append(closure,node);
    if (nodeTree == NULL || nodeTree->children == NULL){
        return closure;
    }
    traverse(nodeTree,closure,nodes);
    return closure;
}

static fs_rid_vector *rdfs_entl_vector(fs_rid_vector *nodes,int type) {
   GHashTable *tree = type == RS_GBL_SUBCLASS ? subClassOf_node : subPropertyOf_node;
   if(!tree) {
        return nodes;
   }
   int lnodes = fs_rid_vector_length(nodes);
   fs_rid_vector *res = fs_rid_vector_new(0);
   for (int k=0;k<lnodes;k++) {
        get_tree_closure(nodes->data[k],tree,res);
   }
   return res;
}

fs_rid_vector *fsr_rdfs_sub_classes_vector(fs_rid_vector *nodes) {
    return rdfs_entl_vector(nodes,RS_GBL_SUBCLASS);
}

fs_rid_vector *fsr_rdfs_subproperties_vector(fs_rid_vector *nodes) {
    fs_rid_vector *res=rdfs_entl_vector(nodes,RS_GBL_SUBPROPERTY);
    return res;

}

static void get_super_nodes(const fs_rid node_rid,GHashTable* nodes,fs_rid_vector *closure) {
    /*if (!fs_rid_vector_length(closure)) {
        fs_rid_vector_append(closure,node_rid);
    }*/

    _rid_node *nodeTree = (_rid_node *) g_hash_table_lookup(nodes,&node_rid);
	if (!nodeTree || !fs_rid_vector_length(nodeTree->parents))
        return;

    fs_rid_vector *parents = nodeTree->parents;
    int pl = fs_rid_vector_length(parents);
    for (int p=0;p<pl;p++) {
        fs_rid rid_parent = parents->data[p];
        nodeTree = (_rid_node *) g_hash_table_lookup(nodes,&rid_parent);
        if(nodeTree && (rid_parent != node_rid)
                && !fs_rid_vector_contains(closure,rid_parent)) {
            fs_rid_vector_append(closure,rid_parent);
            get_super_nodes(rid_parent,nodes,closure);
        }
    }
}

fs_rid *fsr_get_new_quad_for(fs_rid m,fs_rid s,fs_rid p,fs_rid o) {
    fs_rid *cpy_quad = calloc(4, sizeof(fs_rid));
    cpy_quad[0]=m;//ENTAIL_GRAPH;
    cpy_quad[1]=s;
    cpy_quad[2]=p;
    cpy_quad[3]=o;
    return cpy_quad; 
}

int fsr_controlled_append(GPtrArray *arr,fs_rid *quad) {
    if (quad[0] == FS_RID_NULL || quad[0] == ENTAIL_GRAPH) {
        g_ptr_array_add(arr,quad);
        return 1;
    }
    return 0;
}

int fsr_rdfs_extend_quads(const fs_rid source_quad[],GPtrArray *entailments,
                      int bind_flags,int limit,int *count,int reasoning) {

    int added_quads = 0;
    int iindex = 0;

    fs_rid_vector *closure = fs_rid_vector_new(0);

    if (FSR_DO_SC(reasoning) && (source_quad[2] == RDF_TYPE_RID || source_quad[2] == RDFS_SUBCLASS_RID)) {
        iindex = 3;
        if (subClassOf_node != NULL)
            get_super_nodes(source_quad[3],subClassOf_node,closure);
    } else {
        if ((FSR_DO_RAN(reasoning) && source_quad[2] == RDFS_RANGE_RID)
            || (FSR_DO_DOM(reasoning) && source_quad[2] == RDFS_DOMAIN_RID)) {
            iindex = 3;
            fs_rid_vector *vc = NULL;
            if (source_quad[2] == RDFS_RANGE_RID && range_node) 
                vc =(fs_rid_vector *) g_hash_table_lookup(range_node,&source_quad[1]);
            else if (source_quad[2] == RDFS_DOMAIN_RID && domain_node)
                vc =(fs_rid_vector *) g_hash_table_lookup(domain_node,&source_quad[1]);
            if (vc) {
                closure = fs_rid_vector_new(0);
                fs_rid_vector_append_vector_no_nulls(closure,vc);
            }
        } else if (FSR_DO_SP(reasoning) && subPropertyOf_node != NULL) {
            iindex = source_quad[2] == RDFS_SUBPROPERTY_RID ? 3 : 2;
            get_super_nodes(source_quad[iindex],subPropertyOf_node,closure);
        }
    }
    
    int clen = fs_rid_vector_length(closure);
    if (closure && clen!=0) {
        int k;
        for (k=0;k<clen;k++) {
            fs_rid *cpy_quad = fsr_get_new_quad_for(ENTAIL_GRAPH,source_quad[1],source_quad[2],source_quad[3]);
            cpy_quad[iindex] = closure->data[k];
            if (fsr_controlled_append(entailments,cpy_quad)) {
   
            added_quads++;
            if (!(limit > *count))
                return added_quads;
            }
            }
    }
    if (closure) fs_rid_vector_free(closure);
    return added_quads;
}

int fsr_rdfs_extend_quads_domain_range(GHashTable *preds_by_subj,fs_rid_vector *subjects,
                             fs_rid_vector *objects, GPtrArray *entailments,int bind_flags,int *count) {
    #if DEBUG_RDFS > 12
    fs_error(LOG_ERR, "[IN] rdfs_extend_quads_domain %p %p",subjects,objects);
    fs_error(LOG_ERR, "subjects");
    fs_rid_vector_print(subjects,0,stdout);
    fs_error(LOG_ERR, "objects");
    fs_rid_vector_print(objects,0,stdout);
    #endif
    int added_quads=0;
    fs_rid_vector *closure = NULL;
    guint lsubjects = fs_rid_vector_length(subjects);
    fs_rid s_rid;
    for (int i=0;i<lsubjects;i++) {
    s_rid = subjects->data[i];
    GArray *s = (GArray *) g_hash_table_lookup(preds_by_subj,&s_rid);
    #if DEBUG_RDFS > 12
    fs_error(LOG_ERR, "(%d/%d) s_rid %llx types %p",i,lsubjects,s_rid,s);
    #endif
    #if DEBUG_RDFS
        if (!(i % 5000))
            fs_error(FS_ERROR,"progress %u/%u",i,lsubjects);
    #endif
    if (s) {
        fs_rid r; 
        for(int i=0;i<s->len;i++) {
            r=g_array_index(s,fs_rid,i);
            if (closure) fs_rid_vector_free(closure);
            closure = fs_rid_vector_new(0);
            get_super_nodes(r,subClassOf_node,closure);
            int clen = fs_rid_vector_length(closure);
            for (int k=0;k<clen;k++) {
                fs_rid o = closure->data[k];
                if (objects == NULL || fs_rid_vector_contains(objects,o)) {
                    fs_rid *cpy_quad = fsr_get_new_quad_for(ENTAIL_GRAPH,s_rid,RDF_TYPE_RID,closure->data[k]);
                    #if DEBUG_RDFS > 15
                    fs_error(LOG_ERR, "reqd(0) adding [%llx [a] %llx]",s_rid,closure->data[k]);
                    #endif
                    if (fsr_controlled_append(entailments,cpy_quad)) {
                    *count = *count + 1;
                    added_quads++;
                    }
                }
            }
            if (objects == NULL || fs_rid_vector_contains(objects,r)) {
                fs_rid *cpy_quad = fsr_get_new_quad_for(ENTAIL_GRAPH,s_rid,RDF_TYPE_RID,r);
                #if DEBUG_RDFS > 12
                fs_error(LOG_ERR, "reqd(1) adding [%llx [a] %llx]",s_rid,r);
                #endif
                if (fsr_controlled_append(entailments,cpy_quad)) {
                *count = *count + 1;
                added_quads++;
                }
            }
        }
    }
    }
    if (closure) fs_rid_vector_free(closure);
    #if DEBUG_RDFS
    fs_error(LOG_ERR, "added_quads %u",added_quads);
    #endif
    return added_quads;
}

static void extend_table_with(GHashTable *table,GHashTable *hierarchy) {
    if ((g_hash_table_size(table) == 0)  || (g_hash_table_size(hierarchy) == 0 ))
        return;

    GList *tmp,*list = NULL;
    list = g_hash_table_get_keys(hierarchy);
    tmp = list;
    while(tmp) {
        fs_rid *rid = tmp->data;
        fs_rid_vector *d = g_hash_table_lookup(table,rid);
        if (d) {
            fs_rid_vector *c  = get_tree_closure(*rid,hierarchy,NULL);
            int cl = fs_rid_vector_length(c);
            for (int i=0;i<cl;i++) {
               fs_rid_vector *sd = g_hash_table_lookup(table,&c->data[i]);
               if (!sd) {
                    sd = fs_rid_vector_new(0);
                    fs_rid *cpy = malloc(sizeof(fs_rid));
                    *cpy = c->data[i];
                    g_hash_table_insert(table,cpy,sd);
               }
               fs_rid_vector_append_vector(sd,d);
            }
        }
        tmp = g_list_next(tmp);
    }
}

unsigned char *fsr_handle_update_cache(fs_segment segment, unsigned int length, unsigned char *content, int type) {
    fs_rid_vector **binds = fsr_msg_to_mtrx(content);
    if (type == RS_GBL_SUBCLASS) {
         if (subClassOf_node) g_hash_table_destroy(subClassOf_node);
         subClassOf_node = edges_to_tree(binds);
    } 
    else if  (type == RS_GBL_SUBPROPERTY) {
         if (subPropertyOf_node) g_hash_table_destroy(subPropertyOf_node);
         subPropertyOf_node = edges_to_tree(binds);
    } else if (type == RS_GBL_DOMAIN) {
         if (domain_node) g_hash_table_destroy(domain_node);
         domain_node = edges_to_table(binds);
         /* subProperty gets updated always first, so we can do this here */
         extend_table_with(domain_node,subPropertyOf_node);
    } else if (type == RS_GBL_RANGE) {
         if (range_node) g_hash_table_destroy(range_node);
         range_node = edges_to_table(binds);
         /* subProperty gets updated always first, so we can do this here */
         extend_table_with(range_node,subPropertyOf_node);
    } else {
        fs_error(LOG_ERR,"unknown message type in fsr_handle_update_cache");   
    }
    fs_rid_vector_free(binds[0]);
    fs_rid_vector_free(binds[1]);
    free(binds);
    if (cache_dr.lookup) {
        fs_error(FS_ERROR,"init free cache_dr");
        fs_rid_vector_free(cache_dr.keys);
        g_hash_table_destroy(cache_dr.lookup);
        cache_dr.lookup = NULL; 
        cache_dr.keys = NULL; 
        fs_error(FS_ERROR,"end free cache_dr");
    }
    unsigned char *m = message_new(FS_DONE_OK, segment, 0);
    return m;
}

void fsr_print_cache_stats(void) {
    fs_error(LOG_ERR,"subClassOf_node %d subPropertyOf_node %d domain_node %d range_node %d",   
    subClassOf_node ? g_hash_table_size(subClassOf_node) : 0, 
    subPropertyOf_node ? g_hash_table_size(subPropertyOf_node) : 0,
    domain_node ? g_hash_table_size(domain_node) : 0,
    range_node ? g_hash_table_size(range_node) : 0
    );
}
