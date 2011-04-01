
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

fs_rid_vector *get_tree_closure(fs_rid *node,GHashTable* nodes, fs_rid_vector *partial);
void loadRDFSTrees(reasoner_conf *reasoner);
unsigned int send_message(int sckt_cl, char *addr, int port, unsigned char *msg, int len);

static GHashTable* subClassOf_node = NULL;
static GHashTable* subPropertyOf_node = NULL;
static GHashTable* range_node = NULL;
static GHashTable* domain_node = NULL;

//static unsigned char fsp_vermagic[4] = { 'I', 'D', FS_PROTO_VER_MINOR, 0x0 };

GHashTable *get_rdfs_domains(reasoner_conf *reasoner) {
    if (!domain_node)
        loadRDFSTrees(reasoner);
    return domain_node;
}

GHashTable *get_rdfs_ranges(reasoner_conf *reasoner) {
    if (!range_node)
        loadRDFSTrees(reasoner);
    return range_node;
}

GNode *get_node(GHashTable* lookup,fs_rid *rid) {
	GNode *node = (GNode *) g_hash_table_lookup(lookup,rid);
	if (node == NULL) {
		node = g_node_new(rid);
		g_hash_table_insert(lookup,rid,node);
	}
	return node;
}

void add_elto_set(GHashTable* lookup,fs_rid *rid,fs_rid_set *eltos) {
	fs_rid_set *s = (fs_rid_set *) g_hash_table_lookup(lookup,rid);
	if (s == NULL) {
		s = fs_rid_set_new();
        fs_rid *key = calloc(1, sizeof(fs_rid));
        *key=*rid;
		g_hash_table_insert(lookup,key,s);
	}
    fs_rid r; 
    while((r=fs_rid_set_next(eltos))!=FS_RID_NULL) {
        fs_rid_set_add(s,r);
    }
    fs_rid_set_rewind(eltos);
}

void add_1elto_set(GHashTable* lookup,fs_rid *rid,fs_rid *elto) {
	fs_rid_set *s = (fs_rid_set *) g_hash_table_lookup(lookup,rid);
	if (s == NULL) {
		s = fs_rid_set_new();
		g_hash_table_insert(lookup,rid,s);
	}
    fs_rid_set_add(s,*elto);
}

GList *get_assignment_list(unsigned char *mess,GList *origin) {
    unsigned char *data = mess + FS_HEADER;
    unsigned int * const l = (unsigned int *) (mess + 4);
    int elements = *l / sizeof(int);
    GList *ret=NULL;
    int *elto = NULL;
    for(int i=0;i<elements;i++) {
        elto = calloc(1,sizeof(int));
        memcpy(elto,data,sizeof(int));
        data += sizeof(int);
        GList *e = g_list_nth(origin,*elto);
        fs_rid *q = e->data;
        ret=g_list_append(ret,q);
    }
    return ret;
}

unsigned char * request_msg(int type, size_t data_length) {
	unsigned char *buffer = calloc(1, FS_HEADER + data_length);
	unsigned int * const l = (unsigned int *) (buffer + 4);
	*l = (unsigned int) data_length;
	buffer[3] = (unsigned char) type;
	return buffer;
}

GList *get_equads_assignment(fs_segment segment,GList *entailments,reasoner_conf *reasoner) {
    size_t data_length = g_list_length(entailments) * 24;
    unsigned char *buffer = request_msg(RS_QUAD_ASSIGN,data_length); 
    unsigned int * const s = (unsigned int *) (buffer + 8);
    *s = segment;
    unsigned char *data = buffer + FS_HEADER;
    GList *tmp = entailments;
    while(tmp) {
        memcpy(data, tmp->data+8, 24);//+8 to skip q[0] and add q[1,2,3]
        data += 24;
        tmp=g_list_next(tmp); 
    }
    int sckt_cl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    unsigned int count = send_message(sckt_cl,reasoner->addr,reasoner->port,buffer,FS_HEADER + data_length);
    if (count == 0) {
        fs_error(LOG_ERR,"assign message no bytes written on send to %s:%i",
            reasoner->addr,reasoner->port);
        return NULL;
    }        
    unsigned char *resp = reasoner_recv(sckt_cl, &count);
    if (!resp) {
        fs_error(LOG_ERR,"no resp to assign, this potentially provokes duplicates");
    }
    GList *assign = get_assignment_list(resp,entailments);
    if (resp)
        free(resp);
    if (buffer)
        free(buffer);
    g_list_free(entailments);
    return assign;
}


unsigned char * send_receive(unsigned char *msg,size_t len,const char *addr,int port,size_t *resp_len) {
        fs_error(LOG_ERR,"addr %s",addr);
    unsigned char *req = msg;
    struct sockaddr_in st_sckt_addr;
    int sckt_cl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    int res;
    unsigned int count;
    if (-1 == sckt_cl) {
        fs_error(LOG_ERR,"Error creating client soccket");
        return NULL;
    }
    memset(&st_sckt_addr, 0, sizeof(struct sockaddr_in));
    
    st_sckt_addr.sin_family = AF_INET;
    st_sckt_addr.sin_port = htons(port);
    res = inet_pton(AF_INET, addr, &st_sckt_addr.sin_addr);

    if (0 > res) {
      fs_error(LOG_ERR,"error: first parameter is not a valid address family");
      close(sckt_cl);
      return NULL;
    }
    else if (0 == res) {
      fs_error(LOG_ERR,"char string (second parameter does not contain valid ipaddress");
      close(sckt_cl);
      return NULL;
    }

    if (-1 == connect(sckt_cl, (const struct sockaddr *)&st_sckt_addr, sizeof(struct sockaddr_in))) {
      fs_error(LOG_ERR,"connect failed");
      close(sckt_cl);
      return NULL;
    }

    count = write(sckt_cl, req, len);
    *resp_len=(size_t)count;
    unsigned char *resp = reasoner_recv(sckt_cl, &count);
    close(sckt_cl);
    return resp;
}

unsigned int send_message(int sckt_cl,char *addr,int port,unsigned char *msg, int len) {
    struct sockaddr_in st_sckt_addr;
    int res;
    unsigned int count;
    if (-1 == sckt_cl) {
        fs_error(LOG_ERR,"Error creating client socket");
        return 0;
    }
    memset(&st_sckt_addr, 0, sizeof(struct sockaddr_in));
    
    st_sckt_addr.sin_family = AF_INET;
    st_sckt_addr.sin_port = htons(port);
    res = inet_pton(AF_INET, addr, &st_sckt_addr.sin_addr);

    if (0 > res) {
      fs_error(LOG_ERR,"error: first parameter is not a valid address family");
      close(sckt_cl);
      return 0;
    }
    else if (0 == res) {
      fs_error(LOG_ERR,"char string (second parameter does not contain valid ipaddress");
      close(sckt_cl);
      return 0;
    }

    if (-1 == connect(sckt_cl, (const struct sockaddr *)&st_sckt_addr, sizeof(struct sockaddr_in))) {
      fs_error(LOG_ERR,"connect failed");
      close(sckt_cl);
      return 0;
    }

    count = write(sckt_cl, msg, len);
    return count;
}


void notify_import_finished(fs_backend *be) {
    reasoner_conf *reasoner = be->reasoner;
    unsigned char *req = request_msg(RS_NOTIFY_IMPORT,0);
    int sckt_cl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    unsigned int count = send_message(sckt_cl,reasoner->addr,reasoner->port,req,FS_HEADER);
    if (count == 0)
        fs_error(LOG_ERR,"import notification no bytes written on send to %s:%i",reasoner->addr,reasoner->port);
    unsigned char *resp = reasoner_recv(sckt_cl, &count);
    if (resp) {
        #ifdef DEBUG_RDFS
        fs_error(LOG_ERR,"notify import sent");
        #endif
    }
}

gboolean fs_rid_equalr(fs_rid *v1,fs_rid *v2) {
	return *v1==*v2;
}

guint fs_rid_hashr(fs_rid *v) {
	return (guint)(*v);
}

GHashTable* edges_to_tree(fs_rid_vector **edges) {
	GHashTable* node_lookup = g_hash_table_new( (GHashFunc) fs_rid_hashr, (GEqualFunc) fs_rid_equalr);
    //return node_lookup;

	int length = edges[0]->length;
	for (int k = 0; k < length; ++k) {
		fs_rid * superElto = &edges[1]->data[k];
		fs_rid * subElto = &edges[0]->data[k];
		//printf("SUPER:%016llX  SUB:%016llX\n", *superElto, *subElto);
		GNode * superNode = get_node(node_lookup,superElto);
		GNode * subNode = get_node(node_lookup,subElto);
        if (superNode != subNode) {
		//printf("adding %p %p\n", superNode, subNode);
        if (G_NODE_IS_ROOT(subNode)) { //avoiding circle and graphs
		    g_node_append(superNode,subNode);
		    //printf("added %p %p\n", superNode, subNode);
        //} else {
		  //  printf("NOT ROOT NOT added\n");
        }
        }
	}
	return node_lookup;
}

GHashTable* edges_to_table(fs_rid_vector **edges) {
	GHashTable* node_lookup = g_hash_table_new( (GHashFunc) fs_rid_hashr, (GEqualFunc) fs_rid_equalr);

	int length = edges[0]->length;
	for (int k = 0; k < length; ++k) {
		fs_rid * key = &edges[0]->data[k];
		fs_rid * elto = &edges[1]->data[k];
        if (elto != key) {
		//printf("KEY:%016llX  ELTO:%016llX\n", *key, *elto);
            add_1elto_set(node_lookup,key,elto);
        }
	}
	return node_lookup;
}

GHashTable* get_rdfs_data(char *addr,int port,int type) {
    unsigned char *req = request_msg(type,0);
    int sckt_cl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    unsigned int count = send_message(sckt_cl,addr,port,req,FS_HEADER);
    if (count == 0) {
        fs_error(LOG_ERR,"no bytes written on send type %i to  %s:%i",type,addr,port);
        return NULL;
    }
    unsigned char *msg = reasoner_recv(sckt_cl, &count);
    close(sckt_cl);
    fs_rid_vector **binds = msg_to_mtrx(msg);
    #ifdef DEBUG_RDFS
    //int elts = binds ? binds[0]->length : 0;
    //fs_error(LOG_ERR,"requesting reasoner %s:%i type request %c --> %i",addr,port,type,elts);
    #endif
    GHashTable* nodes = NULL;
    if (type == RS_GBL_SUBCLASS || type == RS_GBL_SUBPROPERTY) {
        nodes = edges_to_tree(binds);
    }
    else {
        nodes = edges_to_table(binds);
    }
    return nodes;
}

void extend_table_with(GHashTable *table,GHashTable *hierarchy) {
    if ((g_hash_table_size(table) == 0)  || (g_hash_table_size(hierarchy) == 0 ))
        return;

    GList *tmp,*list = NULL;
    list = g_hash_table_get_keys(hierarchy);
    tmp = list;
    while(tmp) {
        fs_rid *rid = tmp->data;
        fs_rid_set *d = g_hash_table_lookup(table,rid);
        if (d) {
            fs_rid_vector *c  = get_tree_closure(rid,hierarchy,NULL);
            int cl = fs_rid_vector_length(c);
            for (int i=0;i<cl;i++) {
               fs_rid_set *sd = g_hash_table_lookup(table,&c->data[i]);
               if (!sd) {
                    sd = fs_rid_set_new();
                    g_hash_table_insert(table,&c->data[i],sd);
               }
               fs_rid r;
               while((r=fs_rid_set_next(d))!=FS_RID_NULL) {
                    fs_rid_set_add(sd,r);
               }
               fs_rid_set_rewind(d);
            }
            //fs_rid_vector_free(c);
        }
        tmp = g_list_next(tmp);
    }
}

void dumpTable(GHashTable *table) {
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

void loadRDFSTrees(reasoner_conf *reasoner) {
    //fs_error(LOG_ERR, "INIT loadRDFSTrees");
    if (subClassOf_node == NULL) {
        subClassOf_node = get_rdfs_data(reasoner->addr,reasoner->port,RS_GBL_SUBCLASS); 
    }
    if (subPropertyOf_node == NULL) {
        subPropertyOf_node = get_rdfs_data(reasoner->addr,reasoner->port,RS_GBL_SUBPROPERTY); 
    }
    if (range_node == NULL) {
        range_node = get_rdfs_data(reasoner->addr,reasoner->port,RS_GBL_RANGE); 
        extend_table_with(range_node,subPropertyOf_node);
        //dumpTable(range_node);
    }
    if (domain_node == NULL) {
        domain_node = get_rdfs_data(reasoner->addr,reasoner->port,RS_GBL_DOMAIN); 
        //dumpTable(domain_node);
        extend_table_with(domain_node,subPropertyOf_node);
        //dumpTable(domain_node);
    }
    //fs_error(LOG_ERR, "END loadRDFSTrees");
}

gboolean append_to_closure(GNode *node, fs_rid_vector* closure) {
	fs_rid *value = node->data;
    //if (!fs_rid_vector_contains(closure,*value))
	fs_rid_vector_append(closure,*value);
	return 0;
}

void traverse(GNode *node,fs_rid_vector *closure) {
    fs_rid *value = node->data;
    if (!fs_rid_vector_contains(closure,*value))
        fs_rid_vector_append(closure,*value);
    if (node && node->children) {
         int nc = g_node_n_children(node);
         for (int n=0;n<nc;n++) {
            GNode *kid = g_node_nth_child(node,n);
            if (!fs_rid_vector_contains(closure,*(fs_rid *)kid->data))
                traverse(kid,closure);
         }
    }
}

fs_rid_vector *get_tree_closure(fs_rid *node,GHashTable* nodes, fs_rid_vector *partial) {
    if (!nodes) {
        fs_rid_vector *x = fs_rid_vector_new(0);
        fs_rid_vector_append(x,*node);
        return x;
    }
	GNode *nodeTree = (GNode *) g_hash_table_lookup(nodes,node);
    fs_rid_vector *closure = partial != NULL ? partial : fs_rid_vector_new(0);
    if (!fs_rid_vector_contains(closure,*node))
        fs_rid_vector_append(closure,*node);
    if (nodeTree == NULL || nodeTree->children == NULL){
        return closure;
    }
    traverse(nodeTree,closure);
    return closure;
}

fs_rid_vector *rdfs_entl_vector(reasoner_conf* reasoner,fs_rid_vector *nodes,int type) {
   loadRDFSTrees(reasoner);
   GHashTable *tree = type == RS_GBL_SUBCLASS ? subClassOf_node : subPropertyOf_node;
   if(!tree) {
        return nodes;
   }
   int lnodes = fs_rid_vector_length(nodes);
   fs_rid_vector *res = fs_rid_vector_new(0);
   for (int k=0;k<lnodes;k++) {
        get_tree_closure(&nodes->data[k],tree,res);
   }
   return res;
}

fs_rid_vector *rdfs_sub_classes_vector(reasoner_conf *reasoner,fs_rid_vector *nodes) {
    return rdfs_entl_vector(reasoner,nodes,RS_GBL_SUBCLASS);
}

fs_rid_vector *rdfs_subproperties_vector(reasoner_conf *reasoner,fs_rid_vector *nodes) {
    fs_rid_vector *res=rdfs_entl_vector(reasoner,nodes,RS_GBL_SUBPROPERTY);
    return res;

}

fs_rid_vector *rdfs_sub_classes(reasoner_conf *reasoner,fs_rid *node) {
    loadRDFSTrees(reasoner);
    return get_tree_closure(node,subClassOf_node,NULL);
}

fs_rid_vector *rdfs_sub_properties(reasoner_conf *reasoner,fs_rid *node) {
    loadRDFSTrees(reasoner);
    return get_tree_closure(node,subPropertyOf_node,NULL);
}

fs_rid_vector *get_super_nodes(const fs_rid *node,GHashTable* nodes) {
    if (!nodes) {
        fs_rid_vector *x = fs_rid_vector_new(0);
        fs_rid_vector_append(x,*node);
        return x;
    }
	GNode *nodeTree = (GNode *) g_hash_table_lookup(nodes,node);
    fs_rid_vector *closure = fs_rid_vector_new(0);
	if (!nodeTree || !nodeTree->parent)
        return closure;
    nodeTree = nodeTree->parent;
    while(nodeTree && (*((fs_rid *)nodeTree->data) != *node)
            && !fs_rid_vector_contains(closure,*((fs_rid *)nodeTree->data))) {
        append_to_closure(nodeTree,closure);
        nodeTree = nodeTree->parent;
    }
    return closure;
}

fs_rid *get_new_quad_for(fs_rid m,fs_rid s,fs_rid p,fs_rid o) {
    fs_rid *cpy_quad = calloc(4, sizeof(fs_rid));
    cpy_quad[0]=m;//ENTAIL_GRAPH;
    cpy_quad[1]=s;
    cpy_quad[2]=p;
    cpy_quad[3]=o;
    return cpy_quad; 
}

gint compare_quads(const fs_rid *qA,const fs_rid *qB) {
    return ((qA[1] == qB[1]) && (qA[2] == qB[2]) && (qA[3] == qB[3])) ? 0 : 1;
}

int controlled_append(GList **list,fs_rid *quad) {
    if (quad[0] == FS_RID_NULL || quad[0] == ENTAIL_GRAPH) {
    if (!g_list_find_custom(*list,quad,(GCompareFunc) compare_quads)) {
        *list=g_list_append(*list,quad);
        return 1;
    }
    }
    return 0;

}

int rdfs_extend_quads(reasoner_conf *reasoner,const fs_rid source_quad[],GList **entailments,
                      int bind_flags,int limit,int *count) {

    loadRDFSTrees(reasoner);

    int added_quads = 0;
    int iindex = 0;

    fs_rid_vector *closure = NULL;

    if (source_quad[2] == RDF_TYPE_RID || source_quad[2] == RDFS_SUBCLASS_RID) {
        iindex = 3;
        closure = get_super_nodes(&source_quad[3],subClassOf_node);
    } else {
        if (source_quad[2] == RDFS_RANGE_RID || source_quad[2] == RDFS_DOMAIN_RID) {
            iindex = 3;
            fs_rid_set *setc =(fs_rid_set *) g_hash_table_lookup(source_quad[2] == RDFS_RANGE_RID ? 
                                          range_node : 
                                            domain_node,
                                          &source_quad[1]);
            closure = fs_rid_vector_new(0);
            fs_rid_vector_append_set(closure,setc);
        } else {
            iindex = source_quad[2] == RDFS_SUBPROPERTY_RID ? 3 : 2;
            closure = get_super_nodes(&source_quad[iindex],subPropertyOf_node);
        }
    }
    
    int clen = fs_rid_vector_length(closure);
    if (closure && clen!=0) {
        int k;
        for (k=0;k<clen;k++) {
            fs_rid *cpy_quad = get_new_quad_for(ENTAIL_GRAPH,source_quad[1],source_quad[2],source_quad[3]);
            cpy_quad[iindex] = closure->data[k];
            if (controlled_append(entailments,cpy_quad)) {
   
            added_quads++;
            if (!(limit > *count))
                return added_quads;
            }
            }
    }
    if (closure) fs_rid_vector_free(closure);
    return added_quads;
}

int rdfs_extend_quads_domain(reasoner_conf *reasoner, GHashTable *preds_by_subj,fs_rid_vector *subjects,
                             fs_rid_vector *objects, GList **entailments,int bind_flags,int *count) {
    #ifdef DEBUG_RDFS
    fs_error(LOG_ERR, "[IN] rdfs_extend_quads_domain ");
    #endif
    int added_quads=0;
    fs_rid_vector *closure = NULL;
    loadRDFSTrees(reasoner);
    GList *tmp,*list = NULL;
    if (subjects != NULL) {
        int l = fs_rid_vector_length(subjects);
        for (int i=0;i<l;i++)
            list = g_list_append (list,&subjects->data[i]);
    }
    else
        list = g_hash_table_get_keys(preds_by_subj);
    tmp = list;
    while(tmp) {
    fs_rid *s_rid = (fs_rid *)tmp->data;
    fs_rid_set *added_domains = fs_rid_set_new();
    tmp = g_list_next (tmp);
    fs_rid_set *s = (fs_rid_set *) g_hash_table_lookup(preds_by_subj,s_rid);
    #if DEBUG_RDFS > 0
    fs_error(LOG_ERR, "s_rid %llx types %p",*s_rid,s);
    #endif
    if (s) {
    fs_rid r; 
    while((r=fs_rid_set_next(s))!=FS_RID_NULL) {
        closure = get_super_nodes(&r,subClassOf_node);
        int clen = fs_rid_vector_length(closure);
        for (int k=0;k<clen;k++) {
            fs_rid o = closure->data[k];
            if (objects == NULL || fs_rid_vector_contains(objects,o)) {
                if (!fs_rid_set_contains(added_domains,closure->data[k])) {
                fs_rid *cpy_quad = get_new_quad_for(ENTAIL_GRAPH,*s_rid,RDF_TYPE_RID,closure->data[k]);
                #if DEBUG_RDFS > 0
                fs_error(LOG_ERR, "reqd(0) adding [%llx [a] %llx]",*s_rid,closure->data[k]);
                #endif
                if (controlled_append(entailments,cpy_quad)) {
                fs_rid_set_add(added_domains,closure->data[k]);
                *count = *count + 1;
                added_quads++;
                }
                }
            }
        }
        if (objects == NULL || fs_rid_vector_contains(objects,r)) {
            if (!fs_rid_set_contains(added_domains,r)) {
            fs_rid *cpy_quad = get_new_quad_for(ENTAIL_GRAPH,*s_rid,RDF_TYPE_RID,r);
            #if DEBUG_RDFS > 0
            fs_error(LOG_ERR, "reqd(1) adding [%llx [a] %llx]",*s_rid,r);
            #endif
            if (controlled_append(entailments,cpy_quad)) {
            fs_rid_set_add(added_domains,r);
            *count = *count + 1;
            added_quads++;
            }
            }
        }
    }
    fs_rid_set_rewind(s);
    }
    fs_rid_set_free(added_domains);
    }
    if (subjects != NULL) g_list_free(list);
    if (closure) fs_rid_vector_free(closure);
    return added_quads;
}

