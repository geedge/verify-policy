/*************************************************************************
	> File Name: verify_policy.h
	> Author:
	> Mail:
	> Created Time: 2019年08月23日 星期五 18时06分03秒
 ************************************************************************/

#ifndef _VERIFY_POLICY_H
#define _VERIFY_POLICY_H

#include <event2/event.h>
#include "log.h"
#include "utils.h"

struct breakpad_instance;

#define VSYS_ID_MAX 255

enum verify_type
{
    VERIFY_TYPE_POLICY,
    VERIFY_TYPE_REGEX
};

enum compile_table_typle
{
    TSG_TABLE_SECURITY,
    PXY_TABLE_MANIPULATION,
    TSG_TRAFFIC_SHAPING,
    TSG_SERVICE_CHAINGNG,
    PXY_TABLE_INTERCEPT,
    TSG_STATISTICS,
    TSG_MONITOR,
    DOS_PROTECTION,
    TSG_TUNNEL,
    PXY_TABLE_DEFENCE,
    __SCAN_POLICY_MAX
};

enum tsg_obj_table
{
    TSG_OBJ_SOURCE_ADDR,
    TSG_OBJ_DESTINATION_ADDR,
    TSG_OBJ_SUBSCRIBE_ID,
    TSG_OBJ_APP_ID,
	TSG_OBJ_HTTP_URL,
	TSG_OBJ_HTTP_REQ_HDR,
	TSG_OBJ_HTTP_REQ_BODY,
	TSG_OBJ_HTTP_RES_HDR,
	TSG_OBJ_HTTP_RES_BODY,
    TSG_OBJ_SSL_CN,
    TSG_OBJ_SSL_SAN,
    TSG_OBJ_DOH_QNAME,
    TSG_OBJ_DNS_QNAME,
    TSG_OBJ_MAIL_ACCOUNT,
    TSG_OBJ_MAIL_FROM,
    TSG_OBJ_MAIL_TO,
    TSG_OBJ_MAIL_SUBJECT,
    TSG_OBJ_MAIL_CONTENT,
    TSG_OBJ_MAIL_ATT_NAME,
    TSG_OBJ_MAIL_ATT_CONTENT,
    TSG_OBJ_FTP_URI,
    TSG_OBJ_FTP_CONTENT,
    TSG_OBJ_FTP_ACCOUNT,
    TSG_OBJ_SIP_FROM,
    TSG_OBJ_SIP_TO,
    TSG_OBJ_IMSI,
    TSG_OBJ_PHONE_NUMBER,
    TSG_OBJ_APN,
    TSG_OBJ_TUNNEL,
    TSG_OBJ_FLAG,
    TSG_OBJ_GTP_IMEI,
    TSG_OBJ_DST_SERVER_FQDN,
    TSG_OBJ_INTERNAL_ADDR,
    TSG_OBJ_EXTERNAL_ADDR,
    TSG_OBJ_SOURCE_PORT,
    TSG_OBJ_DESTINATION_PORT,
    TSG_OBJ_INTERNAL_PORT,
    TSG_OBJ_EXTERNAL_PORT,
    TSG_OBJ_IP_PROTOCOL,
    TSG_OBJ_SSL_ECH,
    TSG_OBJ_SSL_ESNI,
    TSG_OBJ_SSL_NO_SNI,
    TSG_OBJ_TUNNEL_LEVEL,
    TSG_OBJ_TUNNEL_GTP_ENDPOINT,
    TSG_OBJ_TUNNEL_GRE_ENDPOINT,
    TSG_OBJ_TUNNEL_IP_IN_IP_ENDPOINT,
    __TSG_OBJ_MAX
};

struct verify_policy_thread
{
	int  id;
	pthread_t pid;
	evutil_socket_t accept_fd;
	pthread_attr_t *attr;
	struct evhttp *http;
	struct event_base *base;
	void * (*routine)(void *);
};

struct verify_policy
{
	char name[VERIFY_SYMBOL_MAX];
    struct log_handle *logger;
	unsigned int log_level;
	unsigned int nr_work_threads;
	unsigned int listen_port;
    struct breakpad_instance * breakpad;
	struct verify_policy_thread *work_threads[VERIFY_ARRAY_MAX];
};

extern struct verify_policy * g_verify_proxy;

int verify_policy_table_init(struct verify_policy * verify, const char* profile_path);
void verify_policy_table_free(const char* profile_path);

cJSON *get_library_search_query(const char *data, ssize_t data_len);
cJSON *get_verify_policy_query(const char *data, ssize_t data_len, int thread_id);

void verify_reload_loglevel();

#endif
