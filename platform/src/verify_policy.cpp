/*************************************************************************
	> File Name: verify-policy.cpp
	> Author:
	> Mail:
	> Created Time: 2019年08月23日 星期五 14时41分17秒
 ************************************************************************/
#include<iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <event2/listener.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <cjson/cJSON.h>
#include <event2/buffer.h>

#include <sys/socket.h>//inet_addr
#include <netinet/in.h>//inet_addr
#include <arpa/inet.h>//inet_addr
#include <MESA/stream.h>
#include <sys/stat.h>
#include <libgen.h>

/* Breakpad */
#include <MESA/breakpad_mini.h>

#include <MESA/MESA_prof_load.h>
#include "verify_policy.h"

struct verify_policy * g_verify_proxy = NULL;

/* VERSION STRING */
#ifdef TARGET_GIT_VERSION
static __attribute__((__used__)) const char * git_ver = TARGET_GIT_VERSION;
#else
static __attribute__((__used__)) const char * git_ver = "1.1";
#endif
const char * version()
{
	return git_ver;
}

static int signals[] = {SIGHUP, SIGPIPE, SIGUSR1};

static int load_system_conf(struct verify_policy * verify, const char *profile)
{
    int xret = -1;

    xret = MESA_load_profile_uint_nodef(profile, "CONFIG", "thread-nu", &(verify->nr_work_threads));
    if (xret < 0)
	{
        log_fatal(verify->logger, MODULE_VERIFY_POLICY, "Reading the number of running threads failed");
    }
	xret = MESA_load_profile_short_nodef(profile, "LISTEN", "port", (short *)&(verify->listen_port));
	if (xret < 0)
	{
		log_fatal(verify->logger, MODULE_VERIFY_POLICY, "Reading the listening port failed");
	}
	log_info(verify->logger, MODULE_VERIFY_POLICY, "%s:%d", "The Threads", verify->nr_work_threads);
	log_info(verify->logger, MODULE_VERIFY_POLICY, "%s:%d", "Libevent Port", verify->listen_port);
    return xret;
}

static int evhttp_socket_send(struct evhttp_request *req, char *sendbuf)
{
    struct evbuffer *evb = NULL;

    /* This holds the content we're sending. */
	evb = evbuffer_new();

    if (sendbuf[0] == '\0' && req == NULL){
        goto err;
    }
    evhttp_add_header(evhttp_request_get_output_headers(req),
		              "Content-Type", "application/json");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "keep-alive");
    evbuffer_add_printf(evb, "%s", sendbuf);
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    goto done;

err:
    evhttp_send_error(req, HTTP_NOTFOUND, "Document was not found");
done:
    evbuffer_free(evb);
    return 0;
}

void verify_policy_request_cb(struct evhttp_request *evh_req, void *arg)
{
	char *http_payload_string= NULL; cJSON  *http_payload=NULL;
	struct evbuffer * evbuf_body = NULL;
	char *input = NULL; ssize_t inputlen=0;

	struct verify_policy_thread *thread  = (struct verify_policy_thread *)arg;

	if (evhttp_request_get_command(evh_req) != EVHTTP_REQ_POST)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "FAILED (post type)");
		goto error;
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] Request policy verify: %s", evhttp_request_get_uri(evh_req));

	evbuf_body = evhttp_request_get_input_buffer(evh_req);
	if (!evbuf_body || 0==(inputlen = evbuffer_get_length(evbuf_body)) ||!(input = (char *)evbuffer_pullup(evbuf_body,inputlen)))
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Failed to get post data information.");
		goto error;
	}

 	http_payload = get_verify_policy_query(input, inputlen, thread->id);
	if(http_payload == NULL)
	{
		goto error;
	}

	http_payload_string = cJSON_PrintUnformatted(http_payload);
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[O] %s", http_payload_string);
	evhttp_socket_send(evh_req, http_payload_string);

	cJSON_Delete(http_payload);
	free(http_payload_string);

	goto finish;

error:
	evhttp_send_error(evh_req, HTTP_BADREQUEST, 0);
finish:
	return;
}

void library_search_request_cb(struct evhttp_request *evh_req, void *arg)
{
	struct evbuffer * evbuf_body = NULL;
	char *input = NULL; ssize_t inputlen=0;
	char *http_payload_string= NULL; cJSON  *http_payload=NULL;

	if (evhttp_request_get_command(evh_req) != EVHTTP_REQ_POST)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "FAILED (post type)");
		goto error;
	}

	evbuf_body = evhttp_request_get_input_buffer(evh_req);
	if (!evbuf_body || 0==(inputlen = evbuffer_get_length(evbuf_body)) ||!(input = (char *)evbuffer_pullup(evbuf_body,inputlen)))
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Failed to get post data information.");
		goto error;
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] Request library search: %s", evhttp_request_get_uri(evh_req));

	http_payload = get_library_search_query(input, inputlen);
	if(http_payload == NULL)
	{
		goto error;
	}
	http_payload_string = cJSON_PrintUnformatted(http_payload);
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[O] %s", http_payload_string);
	evhttp_socket_send(evh_req, http_payload_string);

	cJSON_Delete(http_payload);
	free(http_payload_string);

	goto finish;

error:
	evhttp_send_error(evh_req, HTTP_BADREQUEST, 0);
finish:
	return;
}

void * verify_policy_thread_func(void * arg)
{
	struct evhttp_bound_socket *bound = NULL;
	struct verify_policy_thread *thread  = (struct verify_policy_thread *)arg;

    thread->http = evhttp_new(thread->base);
	if (!thread->http)
	{
        log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "couldn'thread create evhttp. Exiting.");
		goto error;
	}

	evhttp_set_cb(thread->http, "/v1/policies/trouble-shooting/policy-verification", verify_policy_request_cb, thread);
	evhttp_set_cb(thread->http, "/v1/policies/trouble-shooting/library-search", library_search_request_cb, thread);

	bound = evhttp_accept_socket_with_handle(thread->http, thread->accept_fd);
	if (bound == NULL)
	{
		goto error;
	}
	log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Work thread %u is run...", thread->id);

	event_base_dispatch(thread->base);
error:
	event_base_free(thread->base);
	return NULL;
}

int create_and_listen_socket(const struct sockaddr *sa, int socklen, int backlog)
{
    int fd;
    int on = 1;
    int family = sa ? sa->sa_family : AF_UNSPEC;
    int socktype = SOCK_STREAM | SOCK_NONBLOCK;

    fd = socket(family, socktype, 0);
    if (fd == -1)
    {
        return fd;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0)
    {
        evutil_closesocket(fd);
        return -1;
    }

    if (bind(fd, sa, socklen) < 0)
    {
        evutil_closesocket(fd);
        return -1;
    }

    listen(fd, backlog);
    return fd;
}

int verify_policy_work_thread_run(struct verify_policy * verify)
{
	int xret = 0;
	struct verify_policy_thread *thread = NULL;

	struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(verify->listen_port);
    evutil_socket_t accept_fd = create_and_listen_socket((struct sockaddr*)&sin, sizeof(struct sockaddr_in), -1);
    if (accept_fd < 0)
	{
        log_fatal(verify->logger, MODULE_VERIFY_POLICY, "Could not create a listen!");
        goto finish;
    }

	for (unsigned tid = 0; tid < verify->nr_work_threads; tid++)
	{
		verify->work_threads[tid] = ALLOC(struct verify_policy_thread, 1);
		thread = verify->work_threads[tid];
		thread->id = tid;
		thread->accept_fd = accept_fd;
		thread->base = event_base_new();
        thread->routine = verify_policy_thread_func;

		if (pthread_create(&thread->pid, thread->attr, thread->routine, thread))
		{
            log_fatal(verify->logger, MODULE_VERIFY_POLICY, "%s", strerror(errno));
			goto finish;
		}
		if (pthread_detach(thread->pid))
		{
            log_fatal(verify->logger, MODULE_VERIFY_POLICY, "%s", strerror(errno));
			goto finish;
		}
	}
finish:
    return xret;
}

void __signal_handler_cb(int sig)
{
	switch (sig)
	{
		case SIGHUP:
			log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Reload log config");
			verify_reload_loglevel();
            break;
		case SIGPIPE:
			break;
		case SIGUSR1:
		case SIGINT:
			break;
		default:
			break;
	}
}

int main(int argc, char * argv[])
{
	const char * main_profile = "./conf/verify_policy.conf";
	struct timespec start_time, end_time;

	int ret = 0, opt = 0, log_level=0;
	while ((opt = getopt(argc, argv, "v")) != -1)
	{
		switch (opt)
		{
			case 'v':
				fprintf(stderr, "Welcome to Verify Policy Engine, Version: %s\n", version());
				return 0;
			default:
				break;
		}
	}
	g_verify_proxy = ALLOC(struct verify_policy, 1);
	assert(g_verify_proxy);
	strcpy(g_verify_proxy->name, "verify_policy");

	int max_file_size_mb=0;
	const char *log_path="./logs/verify_policy.log";
	MESA_load_profile_int_def(main_profile, "SYSTEM", "log_level", &log_level, LOG_FATAL);
	MESA_load_profile_int_def(main_profile, "SYSTEM", "log_file_size_mb", &max_file_size_mb, 0);
	g_verify_proxy->logger = log_handle_create(log_path, log_level);
	if(max_file_size_mb > 0)
	{
		log_handle_set_file_max_size(g_verify_proxy->logger, max_file_size_mb);
	}
	CHECK_OR_EXIT(g_verify_proxy->logger != NULL, "Failed at init log module. Exit.");

	ret = load_system_conf(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at loading profile %s, Exit.", main_profile);

	clock_gettime(CLOCK_REALTIME, &(start_time));
	ret = verify_policy_table_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at init maat module, Exit.");
	clock_gettime(CLOCK_REALTIME, &(end_time));

	log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Read table_info.conf, take time %lu(s)", end_time.tv_sec - start_time.tv_sec);
	printf("Read table_info.conf, take time %lu(s)\n", end_time.tv_sec - start_time.tv_sec);

	g_verify_proxy->breakpad = breakpad_init(main_profile, "system", g_verify_proxy->logger, version());
	CHECK_OR_EXIT(g_verify_proxy->breakpad, "Failed at starting breakpad. Exit.");

	for (size_t i = 0; i < (sizeof(signals) / sizeof(int)); i++)
	{
		signal(signals[i], __signal_handler_cb);
	}

	ret = verify_policy_work_thread_run(g_verify_proxy);

	FOREVER{
        sleep(1);
    }

	return ret;
}

