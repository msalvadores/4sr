#define _GNU_SOURCE


#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <syslog.h>
#include <netdb.h>
#include <glib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>

#include "common/error.h"
#include "common/4store.h"
#include "common/params.h"
#include "4s-reasoner-query.h"
#include "4s-reasoner-common.h"

#define DEFAULT_REASONER_PORT 6789

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

static reasoner_cache *gbl_cache = NULL;
static int cache_loaded = 0;
 
static char * gbl_kb_name = NULL;
static char * gbl_password = NULL;

pthread_mutex_t cntr_warmup = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cntr_quad_assign = PTHREAD_MUTEX_INITIALIZER;

fsp_link *open_kb_link(char *kbname,char *password) {
    fprintf(stderr,"opening %s\n",kbname);
	fsp_link *link = fsp_open_link(kbname, password, FS_OPEN_HINT_RO);
    if (!link) {
        fs_error (LOG_ERR, "couldn't connect to “%s”", kbname);
        exit(2);
    }
    return link;
}


gboolean quad_equal(const fs_rid *qA,const fs_rid *qB) {
    return (qA[1] == qB[1]) && (qA[2] == qB[2]) && (qA[3] == qB[3]);
}


unsigned char *process_quad_assignment(unsigned char *msg, unsigned int length) {
    unsigned char *data = msg + FS_HEADER;
    unsigned int * const s = (unsigned int *) (msg + 8);
    int segment = *s;
    GList *quad_list = NULL;
    unsigned int nquads = length / 24;
    for (int i= 0;i < nquads; i++) {
        fs_rid *quad = calloc(4, sizeof(fs_rid));
        memcpy(quad, data, 24);
        gchar *key = calloc(50 , sizeof(char));
        g_sprintf(key,"%llx_%llx_%llx",quad[0],quad[1],quad[2]);
        gpointer assign = g_hash_table_lookup(gbl_cache->quad_assignment,key);
        if (!assign) {
            g_hash_table_insert(gbl_cache->quad_assignment,key,GINT_TO_POINTER(segment)); 
            quad_list=g_list_append(quad_list,GINT_TO_POINTER(i));
        } else if (GPOINTER_TO_INT(assign) == segment){
            quad_list=g_list_append(quad_list,GINT_TO_POINTER(i));
        }
        data += 24;
    }
    unsigned char *out = list_integer_msg(RS_QUAD_ASSIGN_RESP,quad_list);
    return out;
}

void warmup(reasoner_cache *cache) {

#if 0
printf("press enter\n");
char foo;
read(0, &foo, 1);
#endif

    //FIXME memory leak when warming up free the old binds and messages
    fsp_link *link = open_kb_link(gbl_kb_name,gbl_password);

    cache->subClassOf_bind = rdfs_subclass_stmts(link);
    cache->subClassOf_msg = mtrx_to_msg(RS_GBL_SUBCLASS_RESP,cache->subClassOf_bind,2); 

    cache->subProperty_bind = rdfs_subproperty_stmts(link);
    cache->subProperty_msg = mtrx_to_msg(RS_GBL_SUBPROPERTY_RESP,cache->subProperty_bind,2); 

    cache->range_bind = rdfs_range_stmts(link);
    cache->range_msg = mtrx_to_msg(RS_GBL_RANGE_RESP,cache->range_bind,2); 

    cache->domain_bind = rdfs_domain_stmts(link);
    cache->domain_msg = mtrx_to_msg(RS_GBL_RANGE_RESP,cache->domain_bind,2); 
    
    fsp_close_link(link);
    fprintf(stderr,"cache warmed up [%i subClassOf(s)][%i subPropertyOf(s)][%i domain(s)][%i range(s)] \n",
    cache->subClassOf_bind[0]->length,cache->subProperty_bind[0]->length,
    cache->domain_bind[0]->length,cache->range_bind[0]->length);
}

void process_request(int conn, reasoner_cache *cache) {
    unsigned int length;
    unsigned char *msg = reasoner_recv(conn, &length);
    unsigned char * const type = (unsigned char *) (msg + 3);
    int count;
    if (RS_GBL_SUBCLASS == *type || RS_GBL_SUBPROPERTY == *type ||
        RS_GBL_RANGE == *type || RS_GBL_DOMAIN == *type ) {
        unsigned char * out = NULL;
        if (RS_GBL_SUBCLASS == *type)
            out = cache->subClassOf_msg;
        else if (RS_GBL_SUBPROPERTY == *type)
            out = cache->subProperty_msg;
        else if (RS_GBL_RANGE == *type)
            out = cache->range_msg;
        else if (RS_GBL_DOMAIN)
            out = cache->domain_msg;
        else
            fs_error(LOG_ERR,"Uncontrolled message in 4s-reasoner");
        unsigned int * const l = (unsigned int *) (out + 4);
        count = write(conn, out,(*l)+FS_HEADER);
    } else if (RS_NOTIFY_IMPORT == *type) {
        unsigned char *reply = message_new(FS_DONE_OK, 0, 0);
        count = write(conn, reply,FS_HEADER);
        free(reply);
        int mut_ret = pthread_mutex_trylock(&cntr_warmup);
        if (mut_ret == EBUSY) {
            fs_error(LOG_ERR,"already warming ...");
        } else if (mut_ret == EINVAL) {
            fs_error(LOG_ERR,"error taking mutex");
        } else {
            warmup(gbl_cache);
            pthread_mutex_unlock(&cntr_warmup);
        }
    } else if (RS_QUAD_ASSIGN == *type) {
        int mut_ret = pthread_mutex_lock(&cntr_quad_assign);
        if (mut_ret == EINVAL) {
            fs_error(LOG_ERR,"error taking mutex");
        } else {
            unsigned char *out = process_quad_assignment(msg,length); 
            unsigned int * const l = (unsigned int *) (out + 4);
            count = write(conn, out,(*l)+FS_HEADER);
            pthread_mutex_unlock(&cntr_quad_assign);
            if (out)
                free(out);
         }
    } else {
        fs_error(LOG_ERR, "Unknown type message %c", *type);
    }
}

void default_setup(struct addrinfo *hints) {
  memset(hints, 0, sizeof(struct addrinfo));
  hints->ai_family = AF_UNSPEC;
  hints->ai_socktype = SOCK_STREAM; /* tcp */
  /* no IPv6 without a routeable IPv6 address */
  hints->ai_flags |= AI_ADDRCONFIG;
}

int open_server_socket(uint16_t *port) {
    int on = 1, off = 0, srv, err;
    char cport[6];
    struct addrinfo hints, *info;
    default_setup(&hints);
    /* what we'll do is set IPv6 here and turn off IPV6-only on hosts where it's the default */
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_PASSIVE;
    do {
        sprintf(cport, "%u", *port);
        fs_error(LOG_ERR,"selected port %s",cport);
        if ((err = getaddrinfo(NULL, cport, &hints, &info))) {
          fprintf(stderr, "getaddrinfo failed: %s", gai_strerror(err));
          return -1;
        }
        srv = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
        if (srv < 0) {
          if (errno == EAFNOSUPPORT) {
            fs_error(LOG_INFO, "couldn't get IPv6 dual stack, trying IPv4-only");
            hints.ai_family = AF_INET;
            continue;
          }
          fs_error(LOG_ERR, "socket failed: %s", strerror(errno));
          freeaddrinfo(info);
          return -1;
        }

        if (hints.ai_family != AF_INET && setsockopt(srv, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) == -1) {
          fs_error(LOG_WARNING, "setsockopt IPV6_V6ONLY OFF failed");
        }
        if (setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
          fs_error(LOG_WARNING, "setsockopt SO_REUSEADDR failed");
        }

        if (bind(srv, info->ai_addr, info->ai_addrlen) < 0) {
          if (errno == EADDRINUSE) {
            fs_error(LOG_INFO, "EADDRINUSE picking up next port ...");
            close(srv);
            freeaddrinfo(info);
            
            *port=(*port)+1; /* try another port */
            continue;
          } else {
            fs_error(LOG_ERR, "server socket bind failed: %s", strerror(errno));
            freeaddrinfo(info);
            return -1;
          }
        }
      break;
     } while(1);
    freeaddrinfo(info);
    if (listen(srv, 64) < 0) {
        fs_error(LOG_ERR, "listen failed");
        return -1;
    }
    return srv;

}

void *process_thread(void *arg) {
    GIOChannel *source = (GIOChannel *)arg;
    int conn = accept(g_io_channel_unix_get_fd(source), NULL, NULL);
    if (conn == -1) {
        fs_error(LOG_ERR,"Error opening GIOChannel");
        if (errno != EINTR) fs_error(LOG_ERR, "accept: %s", strerror(errno));
        return NULL; /* try again */
    }
    process_request(conn,gbl_cache); 
    close(conn);
    g_thread_exit(NULL);
    return NULL;
}

gboolean accept_request(GIOChannel *source, GIOCondition condition, gpointer data) {
    errno = 0;
    GError **gt_error=NULL;
    GThread * processing_t =g_thread_create(process_thread, source, FALSE, gt_error);
    if (gt_error)
        fs_error(LOG_ERR,"error creating process_thread %s",(*gt_error)->message);
    return TRUE;
}

void init_main_listener(int srv, reasoner_cache *data) {
    GMainLoop *loop = g_main_loop_new (NULL, FALSE);
    GIOChannel *listener = g_io_channel_unix_new (srv);
    g_io_add_watch(listener, G_IO_IN, accept_request, data);

    g_main_loop_run(loop);
}

static void daemonize (void)
{
  /* fork once, we don't want to be process leader */
  switch(fork()) {
    case 0:
      break;
    case -1:
      fs_error(LOG_ERR, "fork() error starting daemon: %s", strerror(errno));
      exit(1);
    default:
      _exit(0);
  }

  /* new session / process group */
  if (setsid() == -1) {
    fs_error(LOG_ERR, "setsid() failed starting daemon: %s", strerror(errno));
    exit(1);
  }

  /* fork again, separating ourselves from our parent permanently */

  switch(fork()) {
    case 0:
      break;
    case -1:
      fs_error(LOG_ERR, "fork() error starting daemon: %s", strerror(errno));
      exit(1);
    default:
      _exit(0);
  }

  /* close stdin, stdout, stderr */
  close(0); close(1); close(2);

  /* Avahi sucks, we need an open fd or it gets confused -sigh */
  if (open("/dev/null", 0) == -1) {
    fs_error(LOG_ERR, "couldn't open /dev/null: %s", strerror(errno));
  }
  /* use up some more fds as a precaution against printf() getting
     written to the wire */
  open("/dev/null", 0);
  open("/dev/null", 0);

  /* move somewhere safe and known */
  if (chdir("/")) {
    fs_error(LOG_ERR, "chdir failed: %s", strerror(errno));
  }
}

int main(int argc, char **argv){
    int c, opt_index=0, port_arg = DEFAULT_REASONER_PORT, help=0;
    static const char *optstr = "Dp:k:";
    int daemon = 1;
    static struct option longopt[] = {
    { "daemon", 0, 0, 'D' },
    { "port", 0, 0, 'p' },
    { "kb", 0, 0, 'k' },
    { 0, 0, 0, 0 }
    };

    while (( c = getopt_long(argc, argv, optstr, longopt, &opt_index)) != -1) {
        switch (c) {
            case 'D':
              daemon = 0;
              break;
            case 'p':
              port_arg = atoi(optarg);
              break;
            case 'k':
              gbl_kb_name = optarg;
              break;
            default:
              help = 1;
              break;
        }
    }
    if (help || !gbl_kb_name) {
        fprintf(stderr, "Usage: 4s-reasoner -k|--kb <kbname> [-p|--port <port_number>] [-D]\n");
        fprintf(stderr, "If port is omitted then %i will be used as default\n",DEFAULT_REASONER_PORT);
        return 1;
    }
    if (daemon) {
       daemonize();
    }
        
	gbl_password = fsp_argv_password(&argc, argv);

    gbl_cache = calloc(sizeof(reasoner_cache),1);
    gbl_cache->quad_assignment = g_hash_table_new( (GHashFunc) g_str_hash , (GEqualFunc) quad_equal );
    warmup(gbl_cache);
    cache_loaded = 1;
    uint16_t port = port_arg;
    int server_sckt = open_server_socket(&port);    
    if (server_sckt < 0) {
        fprintf(stderr,"Unble to open server socket, exiting ...\n");
        exit(-1);
    }
    fs_error(LOG_INFO,"server socket listening port %i ",port);
    g_thread_init(NULL);
    init_main_listener(server_sckt,gbl_cache);
}
