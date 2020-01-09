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

#include <event2/listener.h>
#include <event2/http.h>
#include <cjson/cJSON.h>
#include <event2/buffer.h>

#include "verify_policy.h"
#include "MESA_prof_load.h"
#include "MESA_handle_logger.h"
#include "verify_policy_logging.h"

struct verify_proxy * g_verify_proxy = NULL;

struct keyword_obj
{
	enum scan_table condition_type;
	char *condition_scope;
	char *keyword;
};

struct verify_policy_query
{
	enum scan_table object_type;
	int addr_type;

	char *clientIp1;
	unsigned int clientPort1;
	char *serverIp1;
	unsigned int serverPort1;

	struct keyword_obj keywords[16];
};

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

extern int pangu_policy_init(struct verify_proxy * verify, const char* profile_path);

static int verify_policy_init(struct verify_proxy * verify, const char *profile)
{
    int xret = -1;

    xret = MESA_load_profile_uint_nodef(profile, "CONFIG", "thread-nu", &(verify->nr_work_threads));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Reading the number of running threads failed");
    }
	xret = MESA_load_profile_short_nodef(profile, "LISTEN", "port", (short *)&(verify->listen_port));
	if (xret < 0){
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Listen Port invalid");
	}
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "%s:%d", "The Threads", verify->nr_work_threads);
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "%s:%d", "Libevent Port", verify->listen_port);
    return xret;
}

enum scan_table verify_type_str2idx(const char *action_str)
{
	const char * table_name[__SCAN_TABLE_MAX];
	table_name[PXY_CTRL_IP] = "ip";
	table_name[PXY_CTRL_HTTP_URL] = "url";
	table_name[PXY_CTRL_HTTP_FQDN] = "fqdn";
	table_name[PXY_CTRL_HTTP_REQ_HDR] = "req_hdr";
	table_name[PXY_CTRL_HTTP_REQ_BODY] = "keywords";
	table_name[PXY_CTRL_HTTP_RES_HDR] = "res_hdr";
	table_name[PXY_CTRL_HTTP_RES_BODY] = "keywords";
	table_name[PXY_CTRL_SUBSCRIBE_ID] = "subscribeid";

	size_t i = 0;

	for (i = 0; i < sizeof(table_name) / sizeof(const char *); i++)
	{
		if (0 == strcasecmp(action_str, table_name[i]))
			break;
	}
	return (enum scan_table)i;
}

struct verify_policy_query *get_query_from_request(const char *data)
{
	int c_num = 0, i = 0;
	char buff[VERIFY_STRING_MAX], *p = NULL;;

	cJSON* data_json = cJSON_Parse(data);
	if(data_json == NULL)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "invalid policy parameter");
		return NULL;
	}
	struct verify_policy_query *query_ctx = ALLOC(struct verify_policy_query, 1);

	cJSON* item = NULL, *subitem = NULL;
	item = cJSON_GetObjectItem(data_json,"objectType");
	if(item && item->type==cJSON_String)
	{
		query_ctx->object_type =verify_type_str2idx(item->valuestring);
	}
	item=cJSON_GetObjectItem(data_json,"addrType");
	if(item && item->type==cJSON_Number)
	{
		query_ctx->addr_type = item->valueint;
	}
	item = cJSON_GetObjectItem(data_json,"clientIp1");
	if(item && item->type==cJSON_String)
	{
		query_ctx->clientIp1 =strdup(item->valuestring);
	}
	item = cJSON_GetObjectItem(data_json,"serverIp1");
	if(item && item->type==cJSON_String)
	{
		query_ctx->serverIp1 =strdup(item->valuestring);
	}
	item = cJSON_GetObjectItem(data_json,"clientPort1");
	if(item && item->type==cJSON_String)
	{
		query_ctx->clientPort1 =atoi(item->valuestring);
	}
	item = cJSON_GetObjectItem(data_json,"serverPort1");
	if(item && item->type==cJSON_String)
	{
		query_ctx->serverPort1 =atoi(item->valuestring);
	}
	p = buff;
	p += snprintf(p, sizeof(buff) - (p - buff), "Query key objectType:%d, addrType:%d, clientIp1:%s, serverIp1:%s, clientPort1:%d, serverPort1:%d",
	query_ctx->object_type, query_ctx->addr_type, query_ctx->clientIp1, query_ctx->serverIp1, query_ctx->clientPort1, query_ctx->serverPort1);
	item = cJSON_GetObjectItem(data_json,"keywordObj");
	if(item && item->type==cJSON_Array)
	{
		c_num=cJSON_GetArraySize(item);
		for (subitem = item->child; subitem != NULL; subitem = subitem->next)
		{
			item = cJSON_GetObjectItem(subitem, "conditionScope");
			if(item && item->type==cJSON_String)
			{
				query_ctx->keywords[i].condition_scope =strdup(item->valuestring);
				query_ctx->keywords[i].condition_type = verify_type_str2idx(item->valuestring);
			}
			item = cJSON_GetObjectItem(subitem, "keywords");
			if(item && item->type==cJSON_String)
			{
				query_ctx->keywords[i].keyword =strdup(item->valuestring);
			}
			i++;
		}
	}
	for (i = 0; i < c_num; i++)
	{
		p += snprintf(p, sizeof(buff) - (p - buff), ", conditionScope:%s, keywords:%s", query_ctx->keywords[i].condition_scope, query_ctx->keywords[i].keyword);
	}
	*p = '\0';
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "%s", buff);
	return query_ctx;
}

char *verify_policy_scan(struct verify_policy_query *policy_query, int thread_id)
{
	int c_num = 0; char *policy_payload= NULL;
	void * ctx = pangu_http_ctx_new(thread_id);

	for (c_num = 0; policy_query->keywords[c_num].keyword != NULL; c_num++)
	{
		struct keyword_obj *key_obj = &policy_query->keywords[c_num];

		if (key_obj->condition_scope == NULL)
			key_obj->condition_type = policy_query->object_type;

		switch(key_obj->condition_type)
		{
			case PXY_CTRL_IP:
				http_scan(key_obj->keyword, EV_HTTP_IP, NULL, 0, ctx);
				break;
			case PXY_CTRL_SUBSCRIBE_ID:
				http_scan(key_obj->keyword, EV_HTTP_SUBSCRIBE_ID, NULL, 0, ctx);
			case PXY_CTRL_HTTP_URL:
				http_scan(key_obj->keyword, EV_HTTP_URL, NULL, 0, ctx);
				break;
			case PXY_CTRL_HTTP_FQDN:
				http_scan(key_obj->keyword, EV_HTTP_FQDN, NULL, 0, ctx);
				break;
			case PXY_CTRL_HTTP_REQ_HDR:
				http_scan(key_obj->keyword, EV_HTTP_REQ_HDR, NULL, 0, ctx);
				break;
			case PXY_CTRL_HTTP_RES_HDR:
				http_scan(key_obj->keyword, EV_HTTP_RESP_HDR, NULL, 0, ctx);
				break;
			case PXY_CTRL_HTTP_REQ_BODY:
			case PXY_CTRL_HTTP_RES_BODY:
				http_scan(key_obj->keyword, EV_HTTP_CONTENT, NULL, 0, ctx);
				break;
			default:
				break;
		}
	}
	policy_payload = web_json_table_add(ctx);

	return policy_payload;
}

static int
evhttp_socket_send(struct evhttp_request *req, char *sendbuf)
{
    struct evbuffer *evb = NULL;

    /* This holds the content we're sending. */
	evb = evbuffer_new();

    if (sendbuf[0] == '\0' && req == NULL){
        goto err;
    }
    evhttp_add_header(evhttp_request_get_output_headers(req),
		              "Content-Type", "text/html");
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

void evhttp_request_cb(struct evhttp_request *evh_req, void *arg)
{
	char *policy_payload= NULL;
	struct evbuffer * evbuf_body = NULL;
	char *input = NULL; ssize_t inputlen=0;
	struct verify_policy_query *policy_query = NULL;

	struct verify_proxy_thread *thread_ctx  = (struct verify_proxy_thread *)arg;

	if (evhttp_request_get_command(evh_req) != EVHTTP_REQ_POST)
	{
		mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "FAILED (post type)");
		goto error;
	}
	evbuf_body = evhttp_request_get_input_buffer(evh_req);
	if (!evbuf_body || 0==(inputlen = evbuffer_get_length(evbuf_body)) ||!(input = (char *)evbuffer_pullup(evbuf_body,inputlen)))
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to get post data information.");
		goto error;
	}
 	policy_query = get_query_from_request(input);
	if (policy_query == NULL)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Data parsing failed.");
		goto error;
	}

	policy_payload = verify_policy_scan(policy_query, thread_ctx->id);
	if (policy_payload)
	{
		mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "%s", policy_payload);
		evhttp_socket_send(evh_req, policy_payload);
		free(policy_payload);
	}
	goto finish;

error:
	evhttp_send_error(evh_req, HTTP_BADREQUEST, 0);
finish:
	return;
}

void * verify_policy_thread(void * arg)
{
	struct evhttp_bound_socket *bound = NULL;
	struct verify_proxy_thread *thread_ctx  = (struct verify_proxy_thread *)arg;

    thread_ctx->base = event_base_new();
	if (! thread_ctx->base)
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Can'thread_ctx allocate event base");
        goto finish;
    }
    thread_ctx->http = evhttp_new(thread_ctx->base);
	if (!thread_ctx->http)
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "couldn'thread_ctx create evhttp. Exiting.");
		goto error;
	}

	evhttp_set_cb(thread_ctx->http, "/v1/policy/verification", evhttp_request_cb, thread_ctx);

	bound = evhttp_accept_socket_with_handle(thread_ctx->http, thread_ctx->accept_fd);
	if (bound != NULL)
	{
		mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Bound(%p) to port %d - Awaiting connections ... ", bound,
						g_verify_proxy->listen_port);
	}
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Work thread %u is run...", thread_ctx->id);

	event_base_dispatch(thread_ctx->base);
error:
	event_base_free(thread_ctx->base);
finish:
	return NULL;
}

static int
evutil_fast_socket_nonblocking(evutil_socket_t fd)
{
#ifdef _WIN32
	return evutil_make_socket_nonblocking(fd);
#else
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		return -1;
	}
	return 0;
#endif
}

static int
evutil_fast_socket_closeonexec(evutil_socket_t fd)
{
#if !defined(_WIN32) && defined(EVENT__HAVE_SETFD)
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		return -1;
	}
#endif
	return 0;
}

evutil_socket_t
evutil_socket_(int domain, int type, int protocol)
{
	evutil_socket_t r;
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
	r = socket(domain, type, protocol);
	if (r >= 0)
		return r;
	else if ((type & (SOCK_NONBLOCK|SOCK_CLOEXEC)) == 0)
		return -1;
#endif
#define SOCKET_TYPE_MASK (~(EVUTIL_SOCK_NONBLOCK|EVUTIL_SOCK_CLOEXEC))
	r = socket(domain, type & SOCKET_TYPE_MASK, protocol);
	if (r < 0)
		return -1;
	if (type & EVUTIL_SOCK_NONBLOCK) {
		if (evutil_fast_socket_nonblocking(r) < 0) {
			evutil_closesocket(r);
			return -1;
		}
	}
	if (type & EVUTIL_SOCK_CLOEXEC) {
		if (evutil_fast_socket_closeonexec(r) < 0) {
			evutil_closesocket(r);
			return -1;
		}
	}
	return r;
}

static evutil_socket_t
evhttp_listen_socket_byuser(const struct sockaddr *sa, int socklen,
                            unsigned flags, int backlog)
{
	evutil_socket_t fd;
	int on = 1;
	int family = sa ? sa->sa_family : AF_UNSPEC;
	int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;

	if (flags & LEV_OPT_CLOSE_ON_EXEC)
		socktype |= EVUTIL_SOCK_CLOEXEC;

	fd = evutil_socket_(family, socktype, 0);
	if (fd == -1)
		return fd;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on))<0)
		goto err;
	if (flags & LEV_OPT_REUSEABLE) {
		if (evutil_make_listen_socket_reuseable(fd) < 0)
			goto err;
	}
	if (flags & LEV_OPT_REUSEABLE_PORT) {
		if (evutil_make_listen_socket_reuseable_port(fd) < 0){
			goto err;
        }
	}
	if (sa) {
		if (bind(fd, sa, socklen)<0)
			goto err;
	}
    if (listen(fd, backlog) == -1) {
        goto err;
    }
	return fd;
err:
	evutil_closesocket(fd);
	return fd;
}

int pangu_policy_work_thread_run(struct verify_proxy * verify)
{
	int xret = 0;
	unsigned int tid = 0;
	struct verify_proxy_thread *thread_ctx = NULL;

	struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(verify->listen_port);
    evutil_socket_t accept_fd = evhttp_listen_socket_byuser((struct sockaddr*)&sin, sizeof(struct sockaddr_in),LEV_OPT_REUSEABLE_PORT|LEV_OPT_CLOSE_ON_FREE, -1);
    if (accept_fd < 0)
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Could not create a listen!");
        goto finish;
    }

	for (tid = 0; tid < verify->nr_work_threads; tid++)
	{
		verify->work_threads[tid] = ALLOC(struct verify_proxy_thread, 1);
		thread_ctx = verify->work_threads[tid];
		thread_ctx->id = tid;
		thread_ctx->accept_fd =accept_fd;
        thread_ctx->routine = verify_policy_thread;

		if (pthread_create(&thread_ctx->pid, thread_ctx->attr, thread_ctx->routine, thread_ctx))
		{
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s", strerror(errno));
			goto finish;
		}
		if (pthread_detach(thread_ctx->pid))
		{
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s", strerror(errno));
			goto finish;
		}
	}
    FOREVER{
        sleep(1);
    }
finish:
    return xret;
}

int main(int argc, char * argv[])
{
	const char * main_profile = "./conf/verify_policy.conf";

	int ret = 0, opt = 0;
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
	g_verify_proxy = ALLOC(struct verify_proxy, 1);
	assert(g_verify_proxy);
	strcpy(g_verify_proxy->name, "verify_policy");

	g_verify_proxy->logger = verify_syslog_init(main_profile);
	CHECK_OR_EXIT(g_verify_proxy->logger != NULL, "Failed at init log module. Exit.");

	ret = verify_policy_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at loading profile %s, Exit.", main_profile);

	ret = pangu_policy_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at init panggu module, Exit.");

	ret = pangu_policy_work_thread_run(g_verify_proxy);

	return ret;
}

