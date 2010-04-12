
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


static GHashTable* subClassOf_node = NULL;
static GHashTable* subPropertyOf_node = NULL;
//static unsigned char fsp_vermagic[4] = { 'I', 'D', FS_PROTO_VER_MINOR, 0x0 };

GNode *get_node(GHashTable* lookup,fs_rid *rid) {
	GNode *node = (GNode *) g_hash_table_lookup(lookup,rid);
	if (node == NULL) {
		node = g_node_new(rid);
		g_hash_table_insert(lookup,rid,node);
	}
	return node;
}


unsigned char * request_msg(int type) {
	size_t data_length = 0;
	unsigned char *buffer = calloc(1, FS_HEADER + data_length);
	unsigned int * const l = (unsigned int *) (buffer + 4);
	*l = (unsigned int) data_length;
	buffer[3] = (unsigned char) type;
	return buffer;
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

unsigned int  send_message(int sckt_cl,char *addr,int port,unsigned char *msg) {
    struct sockaddr_in st_sckt_addr;
    int res;
    unsigned int count;
    if (-1 == sckt_cl) {
        fs_error(LOG_ERR,"Error creating client soccket");
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

    count = write(sckt_cl, msg, FS_HEADER);
    return count;
}


void notify_import_finished(reasoner_conf *reasoner) {
    unsigned char *req = request_msg(RS_NOTIFY_IMPORT);
    int sckt_cl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    unsigned int count = send_message(sckt_cl,reasoner->addr,reasoner->port,req);
    if (count == 0)
        fs_error(LOG_ERR,"import notification no bytes written on send to %s:%i",reasoner->addr,reasoner->port);
    unsigned char *resp = reasoner_recv(sckt_cl, &count);
    if (resp) {
        #ifdef DEBUG_RDFS
        fs_error(LOG_ERR,"notify import sent");
        #endif
    }
}

gboolean fs_rid_equal(fs_rid *v1,fs_rid *v2) {
	return *v1==*v2;
}

guint fs_rid_hash(fs_rid *v) {
	return (guint)(*v);
}

GHashTable* edges_to_closed_tree(fs_rid_vector **edges) {
	GHashTable* node_lookup = g_hash_table_new( (GHashFunc) fs_rid_hash, (GEqualFunc) fs_rid_equal);

	int length = edges[0]->length;
	for (int k = 0; k < length; ++k) {
		fs_rid * superClass = &edges[1]->data[k];
		fs_rid * subClass = &edges[0]->data[k];
		//printf("SUPER:%016llX  SUB:%016llX\n", *superClass, *subClass);
		GNode * superNode = get_node(node_lookup,superClass);
		GNode * subNode = get_node(node_lookup,subClass);
		g_node_append(superNode,subNode);
	}
	return node_lookup;
}

GHashTable* get_rdfs_tree(char *addr,int port,int type) {
    unsigned char *req = request_msg(type);
    #ifdef DEBUG_RDFS
    fs_error(LOG_ERR,"requesting reasoner %s:%i type request %c",addr,port,type);
    #endif
    int sckt_cl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    unsigned int count = send_message(sckt_cl,addr,port,req);
    if (count == 0) {
        fs_error(LOG_ERR,"no bytes written on send type %i to  %s:%i",type,addr,port);
        return NULL;
    }
    unsigned char *msg = reasoner_recv(sckt_cl, &count);
    close(sckt_cl);
    fs_rid_vector **binds = msg_to_mtrx(msg);
    GHashTable* nodes = edges_to_closed_tree(binds);
    return nodes;    
}



void loadRDFSTrees(reasoner_conf *reasoner) {
    if (subClassOf_node == NULL) {
        subClassOf_node = get_rdfs_tree(reasoner->addr,reasoner->port,RS_GBL_SUBCLASS); 
    }
    if (subPropertyOf_node == NULL) {
        subPropertyOf_node = get_rdfs_tree(reasoner->addr,reasoner->port,RS_GBL_SUBPROPERTY); 
    }
}

gboolean append_to_closure(GNode *node, fs_rid_vector* closure) {
	fs_rid *value = node->data;
    if (!fs_rid_vector_contains(closure,*value))
	    fs_rid_vector_append(closure,*value);
	return 0;
}


fs_rid_vector *get_tree_closure(fs_rid *node,GHashTable* nodes, fs_rid_vector *partial) {
    if (!nodes) {
        fs_rid_vector *x = fs_rid_vector_new(0);
        fs_rid_vector_append(x,*node);
        return x;
    }
	GNode *nodeTree = (GNode *) g_hash_table_lookup(nodes,node);
    fs_rid_vector *closure = partial != NULL ? partial : fs_rid_vector_new(0);
	
    if (nodeTree == NULL || nodeTree->children == NULL){
        if (!fs_rid_vector_contains(closure,*node))
            fs_rid_vector_append(closure,*node);
        return closure;
    }
    g_node_traverse(nodeTree, G_IN_ORDER , G_TRAVERSE_ALL , -1 , 
        (GNodeTraverseFunc) append_to_closure , closure);
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
    while(nodeTree
            && !fs_rid_vector_contains(closure,*((fs_rid *)nodeTree->data))) {
        append_to_closure(nodeTree,closure);
        nodeTree = nodeTree->parent;
    }
    return closure;
}

void node_closure(fs_rid * key, GNode *node) {
	fs_rid_set* closure = fs_rid_set_new();
	if (node->children){
		g_node_traverse(node, G_IN_ORDER , G_TRAVERSE_ALL , -1 , 
            (GNodeTraverseFunc) append_to_closure , closure);

	}
}   

void bind_extended_quad(const fs_rid quad[4], int tobind, fs_rid_vector **ret)
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

int rdfs_extend_quads(reasoner_conf *reasoner,const fs_rid source_quad[],fs_rid_vector **bind_target,
                      int bind_flags,int limit,int *count) {

    fs_error(LOG_ERR, "extending quads");
    loadRDFSTrees(reasoner);

    int added_quads = 0;
    int iindex = 0;
    fs_rid_vector *closure = NULL;

    if (source_quad[2] == RDF_TYPE_RID || source_quad[2] == RDFS_SUBCLASS_RID) {
        #ifdef DEBUG_RDFS
        fs_error(LOG_ERR, "subClassOf extension case");
        #endif
        iindex = 3;
        closure = get_super_nodes(&source_quad[3],subClassOf_node);
    } else {
        iindex = source_quad[2] == RDFS_SUBPROPERTY_RID ? 3 : 2;
        #ifdef DEBUG_RDFS
        fs_error(LOG_ERR, "subPropertyOf extension case iindex %i" , iindex);
        #endif
        closure = get_super_nodes(&source_quad[iindex],subPropertyOf_node);
    }
    
    int clen = fs_rid_vector_length(closure);
    if (closure && clen!=0) {
        int k;
        fs_rid cpy_quad[4] = {source_quad[0],source_quad[1],source_quad[2],source_quad[3]};
        for (k=0;k<clen;k++) {
            cpy_quad[iindex] = closure->data[k];
            bind_extended_quad(cpy_quad,bind_flags,bind_target);
            *count = *count + 1;
            added_quads++;
            if (!(limit > *count))
                return added_quads;
        }
        return added_quads;
    }
    return 0;
}
