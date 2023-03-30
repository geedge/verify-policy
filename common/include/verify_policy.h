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

enum compile_table_typle
{
    TSG_TABLE_SECURITY,
    PXY_TABLE_MANIPULATION,
    TSG_TRAFFIC_SHAPING,
    TSG_SERVICE_CHAINGNG,
    PXY_TABLE_DEFENCE,
    __SCAN_POLICY_MAX
};

enum common_scan_table
{
    PXY_COMMON_SOURCE_ADDR,
    PXY_COMMON_DESTINATION_ADDR
};

enum manipulate_sacn_table
{
    PXY_CTRL_SOURCE_ADDR,
    PXY_CTRL_DESTINATION_ADDR,
	PXY_CTRL_HTTP_URL,
	PXY_CTRL_HTTP_HOST,
    PXY_CTRL_HTTP_HOST_CAT,
	PXY_CTRL_HTTP_REQ_HDR,
	PXY_CTRL_HTTP_REQ_BODY,
	PXY_CTRL_HTTP_RES_HDR,
	PXY_CTRL_HTTP_RES_BODY,
	PXY_CTRL_SUBSCRIBE_ID,
    PXY_CTRL_APP_ID,
    PXY_CTRL_DOH_QNAME,
    PXY_CTRL_DOH_HOST,
    PXY_CTRL_DOH_HOST_CAT,
    PXY_CTRL_IMSI,
    PXY_CTRL_PHONE_NUMBER,
    PXY_CTRL_APN,
    PXY_CTRL_IP_SRC_ASN,
	PXY_CTRL_IP_DST_ASN,
	PXY_CTRL_IP_SRC_LOCATION,
	PXY_CTRL_IP_DST_LOCATION,
	__SCAN_TABLE_MAX
};

enum security_scan_table
{
    TSG_SECURITY_SOURCE_ADDR,
    TSG_SECURITY_DESTINATION_ADDR,
	TSG_SECURITY_HTTP_URL,
	TSG_SECURITY_HTTP_HOST,
    TSG_SECURITY_HTTP_HOST_CAT,
	TSG_SECURITY_HTTP_REQ_HDR,
	TSG_SECURITY_HTTP_REQ_BODY,
	TSG_SECURITY_HTTP_RES_HDR,
	TSG_SECURITY_HTTP_RES_BODY,
	TSG_SECURITY_SUBSCRIBE_ID,
    TSG_SECURITY_APP_ID,
    TSG_SECURITY_SSL_SNI,
    TSG_SECURITY_SSL_SNI_CAT,
    TSG_SECURITY_SSL_CN,
    TSG_SECURITY_SSL_CN_CAT,
    TSG_SECURITY_SSL_SAN,
    TSG_SECURITY_SSL_SAN_CAT,
    TSG_SECURITY_DNS_QNAME,
    TSG_SECURITY_QUIC_SNI,
    TSG_SECURITY_QUIC_SNI_CAT,
    TSG_SECURITY_MAIL_ACCOUNT,
    TSG_SECURITY_MAIL_FROM,
    TSG_SECURITY_MAIL_TO,
    TSG_SECURITY_MAIL_SUBJECT,
    TSG_SECURITY_MAIL_CONTENT,
    TSG_SECURITY_MAIL_ATT_NAME,
    TSG_SECURITY_MAIL_ATT_CONTENT,
    TSG_SECURITY_FTP_URI,
    TSG_SECURITY_FTP_CONTENT,
    TSG_SECURITY_FTP_ACCOUNT,
    TSG_SECURITY_SIP_FROM,
    TSG_SECURITY_SIP_TO,
    TSG_SECURITY_IMSI,
    TSG_SECURITY_PHONE_NUMBER,
    TSG_SECURITY_APN,
    TSG_SECURITY_TUNNEL,
    TSG_SECURITY_EXCLUSION_SSL_SNI,
    TSG_SECURITY_FLAG,
    TSG_SECURITY_IP_SRC_ASN,
    TSG_SECURITY_IP_DST_ASN,
    TSG_SECURITY_IP_SRC_LOCATION,
    TSG_SECURITY_IP_DST_LOCATION,
	__SECURITY_TABLE_MAX
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
	enum compile_table_typle table_typle;
	struct request_query_obj verify_object[32];
};

extern struct verify_policy * g_verify_proxy;

void *policy_scan_ctx_new(unsigned int thread_id, int vsys_id, enum compile_table_typle table_typle, int compile_table_id);
void pangu_http_ctx_free(void * pme);
size_t policy_verify_scan(int vsys_id, enum compile_table_typle policy_type, struct request_query_obj *query_obj, cJSON *data_obj, void *pme);
void http_get_scan_status(struct request_query_obj *query_obj, int type, cJSON *attributes, cJSON  *data_obj, void *pme);
int proxy_policy_init(struct verify_policy * verify, const char* profile_path);
int security_policy_init(struct verify_policy * verify, const char* profile_path);
int http_hit_policy_list(int vsys_id, enum compile_table_typle policy_type, int compile_table_id, size_t hit_cnt, cJSON *data_obj, void *pme);
void verify_policy_tunnle_add(void * pme);

#endif
