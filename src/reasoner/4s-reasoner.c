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

fsp_link *open_kb_link(char *kbname,char *password) {
    fprintf(stderr,"opening %s\n",kbname);
	fsp_link *link = fsp_open_link(kbname, password, FS_OPEN_HINT_RO);
    if (!link) {
        fs_error (LOG_ERR, "couldn't connect to “%s”", kbname);
        exit(2);
    }
    return link;
}

void warmup(reasoner_cache *cache) {

#if 0
printf("press enter\n");
char foo;
read(0, &foo, 1);
#endif

    fsp_link *link = open_kb_link(gbl_kb_name,gbl_password);
    if (0 && cache->subClassOf_bind) {
        fs_rid_vector_free(cache->subClassOf_bind[0]);
        fs_rid_vector_free(cache->subClassOf_bind[1]);
        free(cache->subClassOf_bind);
    }
    if (0 && cache->subClassOf_msg)
        free(cache->subClassOf_msg);
    cache->subClassOf_bind = rdfs_subclass_stmts(link);
    cache->subClassOf_msg = mtrx_to_msg(RS_GBL_SUBCLASS_RESP,cache->subClassOf_bind,2); 
    if (0 && cache->subProperty_bind) {
        fs_rid_vector_free(cache->subProperty_bind[0]);
        fs_rid_vector_free(cache->subProperty_bind[1]);
        free(cache->subProperty_bind);
    }
    if (0 && cache->subProperty_msg)
        free(cache->subProperty_msg);
    cache->subProperty_bind = rdfs_subproperty_stmts(link);
    cache->subProperty_msg = mtrx_to_msg(RS_GBL_SUBPROPERTY_RESP,cache->subProperty_bind,2); 
    fsp_close_link(link);
    #ifdef DEBUG_RDFS
    fprintf(stderr,"cache warmed up [%i subClassOf(s)][%i subPropertyOf(s)] \n",
    cache->subClassOf_bind[0]->length,cache->subProperty_bind[0]->length);
    #endif 
}

void process_request(int conn, reasoner_cache *cache) {
    unsigned int length;
    unsigned char *msg = reasoner_recv(conn, &length);
    unsigned char * const type = (unsigned char *) (msg + 3);
    int count;
    if (RS_GBL_SUBCLASS == *type || RS_GBL_SUBPROPERTY == *type) {
        unsigned char * out = RS_GBL_SUBCLASS == *type ? 
                                        cache->subClassOf_msg : cache->subProperty_msg;

        unsigned int * const l = (unsigned int *) (out + 4);
        count = write(conn, out,(*l)+FS_HEADER);
        //fs_rid_vector **result2 = msg_to_mtrx(out);
        //print_binding(result2,2);
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
    pthread_exit(NULL);
}

gboolean accept_request(GIOChannel *source, GIOCondition condition, gpointer data) {
    pthread_t process_t;
    int ret;
    ret = pthread_create( &process_t, NULL, process_thread , (void *)source );
    if (ret != 0)
        fs_error(LOG_ERR,"error creating process_thread %i",ret);
    return TRUE;
}

void init_main_listener(int srv, reasoner_cache *data) {
    GMainLoop *loop = g_main_loop_new (NULL, FALSE);
    GIOChannel *listener = g_io_channel_unix_new (srv);
    g_io_add_watch(listener, G_IO_IN, accept_request, data);

    g_main_loop_run(loop);
}

int main(int argc, char **argv){
    int c, opt_index=0, port_arg = DEFAULT_REASONER_PORT, help=0;
    static const char *optstr = "p:k:";
    static struct option longopt[] = {
    { "port", 0, 0, 'p' },
    { "kb", 0, 0, 'k' },
    { 0, 0, 0, 0 }
    };

    while (( c = getopt_long(argc, argv, optstr, longopt, &opt_index)) != -1) {
        switch (c) {
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
        fprintf(stderr, "Usage: 4s-reasoner -k|--kb <kbname> [-p|--port <port_number>]\n");
        fprintf(stderr, "If port is omitted then %i will be used as default\n",DEFAULT_REASONER_PORT);
        return 1;
    }
        
	gbl_password = fsp_argv_password(&argc, argv);

    gbl_cache = calloc(sizeof(reasoner_cache),1);
    warmup(gbl_cache);
    cache_loaded = 1;
    uint16_t port = port_arg;
    int server_sckt = open_server_socket(&port);    
    if (server_sckt < 0) {
        fprintf(stderr,"Unble to open server socket, exiting ...\n");
        exit(-1);
    }
    fs_error(LOG_INFO,"server socket listening port %i ",port);
    init_main_listener(server_sckt,gbl_cache);
}
