/*************************************************************************
	> File Name: verify-policy.cpp
	> Author:
	> Mail:
	> Created Time: 2019年08月23日 星期五 14时41分17秒
 ************************************************************************/

/* Breakpad */
#include <client/linux/handler/exception_handler.h>
#include <common/linux/http_upload.h>

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

#include <sys/socket.h>//inet_addr
#include <netinet/in.h>//inet_addr
#include <arpa/inet.h>//inet_addr
#include <MESA/stream.h>
#include <sys/stat.h>
#include <libgen.h>

#include "verify_policy.h"
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>
#include "verify_policy_utils.h"
#include "verify_policy_logging.h"

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

extern int proxy_policy_init(struct verify_policy * verify, const char* profile_path);

static int verify_policy_init(struct verify_policy * verify, const char *profile)
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

enum verify_policy_type tsg_policy_type_str2idx(const char *action_str)
{
	const char * policy_name[__SCAN_POLICY_MAX];
	policy_name[PXY_TABLE_SECURITY] = "tsg_security";
	policy_name[PXY_TABLE_MANIPULATION] = "pxy_manipulation";
	policy_name[PXY_TABLE_DEFENCE] = "active_defence";

	size_t i = 0;

	for (i = 0; i < sizeof(policy_name) / sizeof(const char *); i++)
	{
		if (0 == strcasecmp(action_str, policy_name[i]))
			break;
	}
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "[I]   policyType= %s", action_str);
	return (enum verify_policy_type)i;
}

int protoco_field_type_str2idx(enum verify_policy_type type, const char *action_str, char *buff, char **p)
{
	size_t scan_table_max=0;
	const char * table_name[__SECURITY_TABLE_MAX] ={0};

	switch(type)
	{
		case PXY_TABLE_MANIPULATION:
			table_name[PXY_CTRL_SOURCE_ADDR]="TSG_SECURITY_SOURCE_ADDR";
			table_name[PXY_CTRL_DESTINATION_ADDR]="TSG_SECURITY_DESTINATION_ADDR";
			table_name[PXY_CTRL_HTTP_URL] = "TSG_FIELD_HTTP_URL";
			table_name[PXY_CTRL_HTTP_FQDN] = "TSG_FIELD_HTTP_HOST";
			table_name[PXY_CTRL_HTTP_REQ_HDR] = "TSG_FIELD_HTTP_REQ_HDR";
			table_name[PXY_CTRL_HTTP_REQ_BODY] = "TSG_FIELD_HTTP_REQ_BODY";
			table_name[PXY_CTRL_HTTP_RES_HDR] = "TSG_FIELD_HTTP_RES_HDR";
			table_name[PXY_CTRL_HTTP_RES_BODY] = "TSG_FIELD_HTTP_RES_BODY";
			table_name[PXY_CTRL_SUBSCRIBE_ID] = "TSG_OBJ_SUBSCRIBER_ID";
			table_name[PXY_CTRL_APP_ID] = "TSG_OBJ_APP_ID";
			table_name[PXY_CTRL_DOH_QNAME]="TSG_FIELD_DOH_QNAME";
			table_name[PXY_CTRL_DOH_HOST]="TSG_FIELD_DOH_HOST";
			table_name[PXY_CTRL_IMSI]="TSG_FILED_GTP_IMSI";
			table_name[PXY_CTRL_PHONE_NUMBER]="TSG_FILED_GTP_PHONE_NUMBER";
			table_name[PXY_CTRL_APN]="TSG_FILED_GTP_APN";
			scan_table_max = PXY_CTRL_APN;
			break;
		case PXY_TABLE_SECURITY:
			table_name[PXY_SECURITY_SOURCE_ADDR]="TSG_SECURITY_SOURCE_ADDR";
			table_name[PXY_SECURITY_DESTINATION_ADDR]="TSG_SECURITY_DESTINATION_ADDR";
			table_name[PXY_SECURITY_HTTP_URL] = "TSG_FIELD_HTTP_URL";
			table_name[PXY_SECURITY_HTTP_FQDN] = "TSG_FIELD_HTTP_HOST";
			table_name[PXY_SECURITY_HTTP_REQ_HDR] = "TSG_FIELD_HTTP_REQ_HDR";
			table_name[PXY_SECURITY_HTTP_REQ_BODY] = "TSG_FIELD_HTTP_REQ_BODY";
			table_name[PXY_SECURITY_HTTP_RES_HDR] = "TSG_FIELD_HTTP_RES_HDR";
			table_name[PXY_SECURITY_HTTP_RES_BODY] = "TSG_FIELD_HTTP_RES_BODY";
			table_name[PXY_SECURITY_SUBSCRIBE_ID] = "TSG_OBJ_SUBSCRIBER_ID";
			table_name[PXY_SECURITY_APP_ID] = "TSG_OBJ_APP_ID";
			table_name[PXY_SECURITY_HTTPS_SNI] = "TSG_FIELD_SSL_SNI";
			table_name[PXY_SECURITY_HTTPS_CN] = "TSG_FIELD_SSL_CN";
			table_name[PXY_SECURITY_HTTPS_SAN] = "TSG_FIELD_SSL_SAN";
			table_name[PXY_SECURITY_DNS_QNAME] = "TSG_FIELD_DNS_QNAME";
			table_name[PXY_SECURITY_QUIC_SNI] = "TSG_FIELD_QUIC_SNI";
			table_name[PXY_SECURITY_MAIL_ACCOUNT] = "TSG_FIELD_MAIL_ACCOUNT";
			table_name[PXY_SECURITY_MAIL_FROM] = "TSG_FIELD_MAIL_FROM";
			table_name[PXY_SECURITY_MAIL_TO] = "TSG_FIELD_MAIL_TO";
			table_name[PXY_SECURITY_MAIL_SUBJECT] = "TSG_FIELD_MAIL_SUBJECT";
			table_name[PXY_SECURITY_MAIL_CONTENT] = "TSG_FIELD_MAIL_CONTENT";
			table_name[PXY_SECURITY_MAIL_ATT_NAME] = "TSG_FIELD_MAIL_ATT_NAME";
			table_name[PXY_SECURITY_MAIL_ATT_CONTENT] = "TSG_FIELD_MAIL_ATT_CONTENT";
			table_name[PXY_SECURITY_FTP_URI] = "TSG_FIELD_FTP_URI";
			table_name[PXY_SECURITY_FTP_CONTENT] = "TSG_FIELD_FTP_CONTENT";
			table_name[PXY_SECURITY_FTP_ACCOUNT] = "TSG_FIELD_FTP_ACCOUNT";
			table_name[PXY_SECURITY_SIP_FROM]="TSG_FIELD_SIP_ORIGINATOR_DESCRIPTION";
			table_name[PXY_SECURITY_SIP_TO]="TSG_FIELD_SIP_RESPONDER_DESCRIPTION";
			table_name[PXY_SECURITY_IMSI]="TSG_FILED_GTP_IMSI";
			table_name[PXY_SECURITY_PHONE_NUMBER]="TSG_FILED_GTP_PHONE_NUMBER";
			table_name[PXY_SECURITY_APN]="TSG_FILED_GTP_APN";
			table_name[PXY_SECURITY_EXCLUSION_SSL_SNI]="TSG_DECYPTION_EXCLUSION_SSL_SNI";
			scan_table_max = PXY_SECURITY_EXCLUSION_SSL_SNI;
			break;
		case PXY_TABLE_DEFENCE:
			break;
		default:
			break;
	}
	size_t i = 0;
	for (i = 0; i <= scan_table_max; i++)
	{
		if (0 == strcasecmp(action_str, table_name[i]))
			break;
	}
	*p += snprintf(*p, sizeof(buff) - (*p - buff), ", protocolField=%s,%d",action_str, (int)i);

	return i;
}

struct ipaddr *ip_to_stream_addr(const char *clientIp1, unsigned int clientPort1, const char *serverIp1, unsigned int serverPort1, int addr_type)
{
	struct ipaddr *ip_addr = ALLOC(struct ipaddr, 1);
	if(addr_type == 4)
	{
		struct stream_tuple4_v4 *v4_addr = ALLOC(struct stream_tuple4_v4, 1);
		ip_addr->addrtype=ADDR_TYPE_IPV4;
		inet_pton(AF_INET,clientIp1,&(v4_addr->saddr));
		v4_addr->source=htons(clientPort1);
		inet_pton(AF_INET,serverIp1,&(v4_addr->daddr));
		v4_addr->dest=htons(serverPort1);
		ip_addr->v4=v4_addr;
	}
	if(addr_type == 6)
	{
		struct stream_tuple4_v6 *v6_addr = ALLOC(struct stream_tuple4_v6, 1);
		ip_addr->addrtype=ADDR_TYPE_IPV6;
		inet_pton(AF_INET6,clientIp1,&(v6_addr->saddr));
		v6_addr->source=htons(clientPort1);
		inet_pton(AF_INET6,serverIp1,&(v6_addr->daddr));
		v6_addr->dest=htons(serverPort1);
		ip_addr->v6=v6_addr;
	}
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "[I]    attributeName = ip, clientIp1=%s, clientPort1=%d, serverIp=%s, serverPort=%d, addr_type = %d",
		clientIp1, clientPort1, serverIp1, serverPort1, addr_type);

	return ip_addr;
}

void ipaddr_free(struct ipaddr *ip_addr)
{
	if(ip_addr->addrtype==ADDR_TYPE_IPV4)
	{
		free(ip_addr->v4);
	}

	if(ip_addr->addrtype==ADDR_TYPE_IPV6)
	{
		free(ip_addr->v6);
	}
	free(ip_addr);
}

static struct ipaddr * get_ip_from_json(cJSON *attributeValue, char *attributeName)
{
	cJSON* item = NULL;
	int addr_type=0, __attribute__((__unused__))protocol=0;
	const char *Ip=NULL;
	unsigned int Port=0;

	item = cJSON_GetObjectItem(attributeValue,"ip");
	if(item && item->type==cJSON_String) Ip = item->valuestring;
	item = cJSON_GetObjectItem(attributeValue,"port");
	if(item && item->type==cJSON_String) Port =atoi(item->valuestring);
	item = cJSON_GetObjectItem(attributeValue,"protocol");
	if(item && item->type==cJSON_Number) protocol = item->valueint;
	item=cJSON_GetObjectItem(attributeValue,"addrType");
	if(item && item->type==cJSON_Number) addr_type = item->valueint;

	struct ipaddr *ip_addr = NULL;
	if(strcasecmp(attributeName, "source") == 0)
	{
		ip_addr = ip_to_stream_addr(Ip, Port, "0.0.0.0", 0, addr_type);
	}

	if(strcasecmp(attributeName, "destination") == 0)
	{
		ip_addr = ip_to_stream_addr("0.0.0.0", 0, Ip, Port, addr_type);
	}
	return ip_addr;
}

static int get_attribute_from_json(int curr_id, cJSON* subchild, struct verify_policy_query *policy_query)
{
	int xret = -1;
	char buff[VERIFY_STRING_MAX], *p = NULL;
	cJSON* item = NULL, *attributeValue=NULL;

	p = buff;
	item = cJSON_GetObjectItem(subchild, "attributeName");
	if(item && item->type==cJSON_String)
	{
		policy_query->verify_object[curr_id].attri_name = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), "attributeName = %s",policy_query->verify_object[curr_id].attri_name);
	}
	policy_query->verify_object[curr_id].attributes=cJSON_Duplicate(subchild, 1);

	item = cJSON_GetObjectItem(subchild, "tableName");
	if(item && item->type==cJSON_String)
	{
		policy_query->verify_object[curr_id].protocol_field = protoco_field_type_str2idx(policy_query->type, item->valuestring, buff, &p);
		if ((policy_query->type == PXY_TABLE_MANIPULATION && policy_query->verify_object[curr_id].protocol_field == __SCAN_TABLE_MAX)
			|| (policy_query->type == PXY_TABLE_SECURITY && policy_query->verify_object[curr_id].protocol_field == __SECURITY_TABLE_MAX))
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "policy table name error, table name = %s", item->valuestring);
			goto finish;
		}
	}
	attributeValue = cJSON_GetObjectItem(subchild, "attributeValue");
	if(attributeValue == NULL || attributeValue->type!=cJSON_Object)
	{
		goto finish;
	}
	if(0 == strcasecmp(policy_query->verify_object[curr_id].attri_name, "source") ||
	   0 == strcasecmp(policy_query->verify_object[curr_id].attri_name, "destination"))
	{
		policy_query->verify_object[curr_id].ip_addr = get_ip_from_json(attributeValue, policy_query->verify_object[curr_id].attri_name);
		goto end;
	}

	item = cJSON_GetObjectItem(attributeValue,"district");
	if(item!=NULL)
	{
		policy_query->verify_object[curr_id].district = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", district = %s",policy_query->verify_object[curr_id].district);
	}

	item = cJSON_GetObjectItem(attributeValue,"string");
	if(item!=NULL)
	{
		policy_query->verify_object[curr_id].keyword = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", content = %s",policy_query->verify_object[curr_id].keyword);
	}
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "[I]    %s", buff);
	memset(buff, 0, VERIFY_STRING_MAX);
end:
	xret = 1;
finish:
	return xret;
}

cJSON *get_query_from_request(const char *data, int thread_id)
{
	int i = 0;
	int hit_cnt = 0, xret =0;
	struct verify_policy_query *verify_policy = NULL;

	cJSON* data_json = cJSON_Parse(data);
	if(data_json == NULL)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "invalid policy parameter");
		return NULL;
	}
	cJSON  *policy_obj=NULL, *data_obj=NULL;
	policy_obj=cJSON_CreateObject();

	cJSON_AddNumberToObject(policy_obj, "code", 200);
	cJSON_AddStringToObject(policy_obj, "msg", "Success");

	data_obj = cJSON_CreateObject();
	cJSON_AddItemToObject(policy_obj, "data", data_obj);

	cJSON* item = NULL, *subitem = NULL, *subchild = NULL, *attributes=NULL;
	item = cJSON_GetObjectItem(data_json,"verifyList");
	if(item && item->type==cJSON_Array)
	{
		for (subitem = item->child; subitem != NULL; subitem = subitem->next)
		{
			verify_policy = ALLOC(struct verify_policy_query, 1);
			item = cJSON_GetObjectItem(subitem,"policyType");
			if(item && item->type==cJSON_String)
			{
				verify_policy->type = tsg_policy_type_str2idx(item->valuestring);
				if (verify_policy->type >= __SCAN_POLICY_MAX)
				{
					mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "policy type error, policy id = %d", verify_policy->type);
					goto free;
				}
			}
			item = cJSON_GetObjectItem(subitem,"verifySession");
			if(item == NULL || item->type!=cJSON_Object)
			{
				goto free;
			}
			attributes = cJSON_GetObjectItem(item,"attributes");
			if(attributes && attributes->type==cJSON_Array)
			{
				void *ctx = pangu_http_ctx_new(thread_id);

				for (subchild = attributes->child; subchild != NULL; subchild = subchild->next)
				{
					xret = get_attribute_from_json(i, subchild, verify_policy);
					if (xret < 0)
					{
						goto free;
					}
					hit_cnt = verify_policy_scan(verify_policy->type, &verify_policy->verify_object[i], data_obj, ctx);
					if(0 == strcasecmp(verify_policy->verify_object[i].attri_name, "source") ||
					   0 == strcasecmp(verify_policy->verify_object[i].attri_name, "destination"))
					{
						ipaddr_free(verify_policy->verify_object[i].ip_addr);
					}
					i++;
				}
				http_hit_policy_list(verify_policy->type, hit_cnt, data_obj, ctx);

				int item = 0;
				cJSON *verfifySession = cJSON_CreateObject();
				cJSON_AddItemToObject(data_obj, "verifySession", verfifySession);
				cJSON *attributes=cJSON_CreateArray();
				cJSON_AddItemToObject(verfifySession, "attributes", attributes);
				for (item = 0; item < i; item++)
				{
					http_get_scan_status(&verify_policy->verify_object[item], verify_policy->type, attributes,data_obj, ctx);
				}
				pangu_http_ctx_free(ctx);
			}

			i=0;
			FREE(&verify_policy);
		}
		goto end;
free:
		if (verify_policy)
		{
			FREE(&verify_policy);
		}
end:
		if (hit_cnt >= 0)
		{
			cJSON_AddBoolToObject(policy_obj, "success", true);
		}
		else
		{
			cJSON_AddBoolToObject(policy_obj, "success", false);
		}
	}
	cJSON_Delete(data_json);
	return policy_obj;
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

void evhttp_request_cb(struct evhttp_request *evh_req, void *arg)
{
	char *policy_payload= NULL; cJSON  *policy_obj;
	struct evbuffer * evbuf_body = NULL;
	char *input = NULL; ssize_t inputlen=0;

	struct verify_policy_thread *thread_ctx  = (struct verify_policy_thread *)arg;

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

 	policy_obj = get_query_from_request(input, thread_ctx->id);
	if(policy_obj == NULL)
	{
		goto error;
	}

	policy_payload = cJSON_PrintUnformatted(policy_obj);
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "[O]   %s", policy_payload);
	evhttp_socket_send(evh_req, policy_payload);

	cJSON_Delete(policy_obj);
	free(policy_payload);

	goto finish;

error:
	evhttp_send_error(evh_req, HTTP_BADREQUEST, 0);
finish:
	return;
}

void * verify_policy_thread_func(void * arg)
{
	struct evhttp_bound_socket *bound = NULL;
	struct verify_policy_thread *thread_ctx  = (struct verify_policy_thread *)arg;

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

	evhttp_set_cb(thread_ctx->http, "/v1/policy/verify", evhttp_request_cb, thread_ctx);

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

int pangu_policy_work_thread_run(struct verify_policy * verify)
{
	int xret = 0;
	unsigned int tid = 0;
	struct verify_policy_thread *thread_ctx = NULL;

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
		verify->work_threads[tid] = ALLOC(struct verify_policy_thread, 1);
		thread_ctx = verify->work_threads[tid];
		thread_ctx->id = tid;
		thread_ctx->accept_fd =accept_fd;
        thread_ctx->routine = verify_policy_thread_func;

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

struct breakpad_instance
{
	unsigned int en_breakpad;
	char minidump_dir_prefix[VERIFY_STRING_MAX];
	google_breakpad::ExceptionHandler * exceptionHandler;

	/* Upload to crash server */
	unsigned int en_breakpad_upload;
	char minidump_sentry_upload_url[VERIFY_STRING_MAX];

	/* Upload tools name */
	char upload_tools_filename[VERIFY_STRING_MAX];

	/* Upload tools exec command */
	char * upload_tools_exec_argv[64];
	char * minidump_filename;
};

static void _mkdir(const char *dir)
{
	char tmp[PATH_MAX];
	char * p = NULL;
	size_t len;

	snprintf(tmp, sizeof(tmp), "%s", dir);
	len = strlen(tmp);
	if (tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for (p = tmp + 1; *p; p++)
	{
		if (*p == '/')
		{
			*p = 0;
			mkdir(tmp, S_IRWXU);
			*p = '/';
		}
	}
	mkdir(tmp, S_IRWXU);
}

int breakpad_init_minidump_upload(struct breakpad_instance * instance, const char * profile)
{
	int ret = 0;
	char execpath[PATH_MAX] = {};
	char * execdirname = NULL;

	ret = MESA_load_profile_string_nodef(profile, "system", "breakpad_upload_url",
		instance->minidump_sentry_upload_url, sizeof(instance->minidump_sentry_upload_url));

	if (unlikely(ret < 0))
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "breakpad_upload_url is necessary, failed. ");
		goto errout;
	}

	ret = readlink("/proc/self/exe", execpath, sizeof(execpath));
	if(unlikely(ret < 0))
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed at readlink /proc/self/exec: %s", strerror(errno));
		/* after log, reset errno */
		errno = 0;
		goto errout;
	}

	execdirname = dirname(execpath);
	snprintf(instance->upload_tools_filename, sizeof(instance->upload_tools_filename) - 1,
		"%s/%s", execdirname, "minidump_upload");


	/* Execfile */
	instance->upload_tools_exec_argv[0] = strdup(instance->upload_tools_filename);

	/* Firstly, Product Name and Product Version */
	instance->upload_tools_exec_argv[1] = strdup("-p");
	instance->upload_tools_exec_argv[2] = strdup("tfe");
	instance->upload_tools_exec_argv[3] = strdup("-v");
	instance->upload_tools_exec_argv[4] = strdup(version());

	/* Minidump file location, now we don't know it */
	instance->minidump_filename = (char *)ALLOC(char, PATH_MAX);
	instance->upload_tools_exec_argv[5] = instance->minidump_filename;

	/* Minidup upload url */
	instance->upload_tools_exec_argv[6] = strdup(instance->minidump_sentry_upload_url);
	instance->upload_tools_exec_argv[7] = NULL;
	return 0;

errout:
	return -1;
}

static bool tfe_breakpad_dump_to_file(const google_breakpad::MinidumpDescriptor& descriptor,
	void* context, bool succeeded)
{
	fprintf(stderr, "Crash happened, minidump path:  %s\n", descriptor.path());
	return succeeded;
}

static bool tfe_breakpad_dump_and_report(const google_breakpad::MinidumpDescriptor& descriptor,
	void* context, bool succeeded)
{
	struct breakpad_instance * instance = g_verify_proxy->breakpad;
	int ret = 0;

	strncpy(instance->minidump_filename, descriptor.path(),  PATH_MAX - 1);
	fprintf(stderr, "Crash happened, prepare upload the minidump file:  %s\n", descriptor.path());

	ret = access(instance->minidump_filename, F_OK | R_OK);
	if (ret < 0)
	{
		fprintf(stderr, "minidump file is not existed, cannot upload minidump file");
		return succeeded;
	}

	/* Firstly, fork an child process */
	pid_t exec_child_pid = fork();
	if (exec_child_pid == 0)
	{
		/* As a child, exec minidump upload tools */
		ret = execv(instance->upload_tools_filename, instance->upload_tools_exec_argv);
		if (ret < 0)
		{
			fprintf(stderr, "Failed at exec the upload program %s: %s\n",
				instance->upload_tools_filename, strerror(errno));
			/* after log, reset errno */
			errno = 0;
		}

		exit(EXIT_FAILURE);
	}
	else if (exec_child_pid > 0)
	{
		fprintf(stderr, "Starting upload minidump, PID = %d. \n", exec_child_pid);
		return succeeded;
	}
	else
	{
		/* failed at fork, cannot upload the minidump */
		fprintf(stderr, "Failed at fork(), cannot upload minidump file. :  %s\n", strerror(errno));
		/* after log, reset errno */
		errno = 0;
		return succeeded;
	}
}

struct breakpad_instance * breakpad_init(const char * profile)
{
	struct breakpad_instance * instance = ALLOC(struct breakpad_instance, 1);
	assert(instance != nullptr);

	int ret = 0;
	unsigned int disable_coredump;
	MESA_load_profile_uint_def(profile, "system", "disable_coredump", &disable_coredump, 0);
	if (disable_coredump > 0)
	{
		const struct rlimit __rlimit_vars = {.rlim_cur = 0, .rlim_max = 0};
		ret = setrlimit(RLIMIT_CORE, &__rlimit_vars);
		if (ret < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "setrlimit(RLIMIT_CORE, 0) failed: %s", strerror(errno));
			/* after log, reset errno */
			errno = 0;
		}
	}

	MESA_load_profile_uint_def(profile, "system", "enable_breakpad", &instance->en_breakpad, 1);
	if (instance->en_breakpad <= 0)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Breakpad Crash Reporting System is disabled. ");
		return instance;
	}

	MESA_load_profile_string_def(profile, "system", "breakpad_minidump_dir",
		instance->minidump_dir_prefix, sizeof(instance->minidump_dir_prefix), "/tmp/crashreport");

	MESA_load_profile_uint_def(profile, "system", "enable_breakpad_upload",
		&instance->en_breakpad_upload, 0);

	/* Create the minidump dir if it is not existed */
	_mkdir(instance->minidump_dir_prefix);

	if (instance->en_breakpad_upload)
	{
		/* Try to init the breakpad upload */
		ret = breakpad_init_minidump_upload(instance, profile);
		if (ret < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Breakpad upload init failed, using local breakpad dumpfile");
			instance->en_breakpad_upload = 0;
		}

		/* When we use breakpad, do not generate any coredump file */
		const struct rlimit __rlimit_vars = {.rlim_cur = 0, .rlim_max = 0};
		ret = setrlimit(RLIMIT_CORE, &__rlimit_vars);
		if (ret < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "setrlimit(RLIMIT_CORE, 0) failed: %s", strerror(errno));
			/* after log, reset errno */
			errno = 0;
		}
	}

	if (instance->en_breakpad_upload)
	{
		instance->exceptionHandler = new google_breakpad::ExceptionHandler(
			google_breakpad::MinidumpDescriptor(instance->minidump_dir_prefix), NULL,
			tfe_breakpad_dump_and_report, NULL, true, -1);
	}
	else
	{
		instance->exceptionHandler = new google_breakpad::ExceptionHandler(
			google_breakpad::MinidumpDescriptor(instance->minidump_dir_prefix), NULL,
			tfe_breakpad_dump_to_file, NULL, true, -1);
	}
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Breakpad Crash Report is enable. ");
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Minidump Dir: %s", instance->minidump_dir_prefix);
	return instance;
}

void __signal_handler_cb(int sig)
{
	switch (sig)
	{
		case SIGHUP:
			mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Reload log config");
            MESA_handle_runtime_log_reconstruction(NULL);
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
	g_verify_proxy = ALLOC(struct verify_policy, 1);
	assert(g_verify_proxy);
	strcpy(g_verify_proxy->name, "verify_policy");

	clock_gettime(CLOCK_REALTIME, &(start_time));

	g_verify_proxy->logger = verify_syslog_init(main_profile);
	CHECK_OR_EXIT(g_verify_proxy->logger != NULL, "Failed at init log module. Exit.");

	ret = verify_policy_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at loading profile %s, Exit.", main_profile);

	ret = proxy_policy_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at init panggu module, Exit.");

	clock_gettime(CLOCK_REALTIME, &(end_time));
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Read table_info_proxy.conf, take time %lu(s)", end_time.tv_sec - start_time.tv_sec);
	printf("Read table_info_proxy.conf, take time %lu(s)\n", end_time.tv_sec - start_time.tv_sec);

	clock_gettime(CLOCK_REALTIME, &(start_time));
	ret = security_policy_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at init security module, Exit.");
	clock_gettime(CLOCK_REALTIME, &(end_time));
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Read table_info_security.conf, take time %lu(s)", end_time.tv_sec - start_time.tv_sec);
	printf("Read table_info_security.conf, take time %lu(s)\n", end_time.tv_sec - start_time.tv_sec);

	g_verify_proxy->breakpad = breakpad_init(main_profile);
	CHECK_OR_EXIT(g_verify_proxy->breakpad, "Failed at starting breakpad. Exit.");

	for (size_t i = 0; i < (sizeof(signals) / sizeof(int)); i++)
	{
		signal(signals[i], __signal_handler_cb);
	}

	ret = pangu_policy_work_thread_run(g_verify_proxy);

	return ret;
}

