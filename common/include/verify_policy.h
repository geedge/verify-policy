/*************************************************************************
	> File Name: verify_policy.h
	> Author:
	> Mail:
	> Created Time: 2019年08月23日 星期五 18时06分03秒
 ************************************************************************/

#ifndef _VERIFY_POLICY_H
#define _VERIFY_POLICY_H

#include <event2/event.h>
#include "verify_policy_utils.h"

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
	TSG_OBJ_HTTP_HOST,
    TSG_OBJ_HTTP_HOST_CAT,
	TSG_OBJ_HTTP_REQ_HDR,
	TSG_OBJ_HTTP_REQ_BODY,
	TSG_OBJ_HTTP_RES_HDR,
	TSG_OBJ_HTTP_RES_BODY,
    TSG_OBJ_SSL_SNI,
    TSG_OBJ_SSL_SNI_CAT,
    TSG_OBJ_SSL_CN,
    TSG_OBJ_SSL_CN_CAT,
    TSG_OBJ_SSL_SAN,
    TSG_OBJ_SSL_SAN_CAT,
    TSG_OBJ_DOH_QNAME,
    TSG_OBJ_DOH_HOST,
    TSG_OBJ_DOH_HOST_CAT,
    TSG_OBJ_DNS_QNAME,
    TSG_OBJ_QUIC_SNI,
    TSG_OBJ_QUIC_SNI_CAT,
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
    TSG_OBJ_IP_SRC_ASN,
	TSG_OBJ_IP_DST_ASN,
	TSG_OBJ_IP_SRC_LOCATION,
	TSG_OBJ_IP_DST_LOCATION,
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
	void * logger;
	unsigned int log_level;
	unsigned int nr_work_threads;
	unsigned int listen_port;
    struct breakpad_instance * breakpad;
	struct verify_policy_thread *work_threads[VERIFY_ARRAY_MAX];
};

struct request_query_obj
{
	int table_id;

    int numeric;
	char *keyword;
    char *district;
	char *attri_name;

    int protocol;
	struct ipaddr *ip_addr;
    struct ipaddr *endpoint;

	char *subscriberid;

    int nth_scan[256];
    int nth_scan_num;
    cJSON* attributes;

    int category_user_num;
    unsigned int category_id_user[8];

    int category_built_num;
    unsigned int category_id_built[8];
};

struct verify_policy_query
{
    int vsys_id;
	int compile_table_id;
	struct request_query_obj verify_object[32];
};

extern struct verify_policy * g_verify_proxy;

void *policy_scan_ctx_new(unsigned int thread_id, int vsys_id, int compile_table_id);
void policy_scan_ctx_free(void * pme);
size_t policy_verify_scan(int vsys_id, int compile_table_id, struct request_query_obj *query_obj, void *pme);
void http_get_scan_status(struct request_query_obj *query_obj, int type, cJSON *attributes, cJSON  *data_obj, void *pme);
int maat_table_init(struct verify_policy * verify, const char* profile_path);
int http_hit_policy_list(struct verify_policy_query *verify_policy, int num, size_t hit_cnt, cJSON *data_obj, void *pme);
void verify_policy_tunnle_add(void * pme);
int policy_verify_regex_expression(const char *expression);

#endif
