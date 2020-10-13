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

enum verify_policy_type
{
    PXY_TABLE_SECURITY,
    PXY_TABLE_MANIPULATION,
    PXY_TABLE_DEFENCE,
    __SCAN_POLICY_MAX
};

enum manipulate_sacn_table
{
    PXY_CTRL_SOURCE_ADDR,
    PXY_CTRL_DESTINATION_ADDR,
	PXY_CTRL_HTTP_URL,
	PXY_CTRL_HTTP_FQDN,
	PXY_CTRL_HTTP_REQ_HDR,
	PXY_CTRL_HTTP_REQ_BODY,
	PXY_CTRL_HTTP_RES_HDR,
	PXY_CTRL_HTTP_RES_BODY,
	PXY_CTRL_SUBSCRIBE_ID,
    PXY_CTRL_APP_ID,
    PXY_CTRL_DOH_QNAME,
    PXY_CTRL_DOH_HOST,
    PXY_CTRL_IP_SRC_ASN,
	PXY_CTRL_IP_DST_ASN,
	PXY_CTRL_IP_SRC_LOCATION,
	PXY_CTRL_IP_DST_LOCATION,
	__SCAN_TABLE_MAX
};

enum security_scan_table
{
    PXY_SECURITY_SOURCE_ADDR,
    PXY_SECURITY_DESTINATION_ADDR,
	PXY_SECURITY_HTTP_URL,
	PXY_SECURITY_HTTP_FQDN,
	PXY_SECURITY_HTTP_REQ_HDR,
	PXY_SECURITY_HTTP_REQ_BODY,
	PXY_SECURITY_HTTP_RES_HDR,
	PXY_SECURITY_HTTP_RES_BODY,
	PXY_SECURITY_SUBSCRIBE_ID,
    PXY_SECURITY_APP_ID,
    PXY_SECURITY_HTTPS_SNI,
    PXY_SECURITY_HTTPS_CN,
    PXY_SECURITY_HTTPS_SAN,
    PXY_SECURITY_DNS_QNAME,
    PXY_SECURITY_QUIC_SNI,
    PXY_SECURITY_MAIL_ACCOUNT,
    PXY_SECURITY_MAIL_FROM,
    PXY_SECURITY_MAIL_TO,
    PXY_SECURITY_MAIL_SUBJECT,
    PXY_SECURITY_MAIL_CONTENT,
    PXY_SECURITY_MAIL_ATT_NAME,
    PXY_SECURITY_MAIL_ATT_CONTENT,
    PXY_SECURITY_FTP_URI,
    PXY_SECURITY_FTP_CONTENT,
    PXY_SECURITY_FTP_ACCOUNT,
    PXY_SECURITY_IP_SRC_ASN,
    PXY_SECURITY_IP_DST_ASN,
    PXY_SECURITY_IP_SRC_LOCATION,
    PXY_SECURITY_IP_DST_LOCATION,
	__SECURITY_TABLE_MAX
};

enum http_ev_bit_number
{
	IP_BITNUM = 0,
	URL_BITNUM,
	FQDN_BITNUM,
	REQ_HDR_BITNUM,
	RESP_HDR_BITNUM,
	CONTENT_BITNUM,
	SUBSCRIBE_ID
};

enum tfe_http_event
{
	EV_HTTP_IP = 1ULL << IP_BITNUM,
	EV_HTTP_URL = 1ULL << URL_BITNUM,
	EV_HTTP_FQDN = 1ULL << FQDN_BITNUM,
	EV_HTTP_REQ_HDR = 1ULL << REQ_HDR_BITNUM,
	EV_HTTP_RESP_HDR = 1ULL << RESP_HDR_BITNUM,
	EV_HTTP_CONTENT = 1ULL << CONTENT_BITNUM,
	EV_HTTP_SUBSCRIBE_ID = 1ULL << SUBSCRIBE_ID,
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

struct verify_policy_query_obj
{
	int protocol_field;

	char *keyword;
	char *attri_name;

	struct ipaddr *ip_addr;

	char *subscriberid;

    int nth_scan;
    cJSON* attributes;

};

struct verify_policy_query
{
	enum verify_policy_type type;
	struct verify_policy_query_obj verify_object[32];
};

extern struct verify_policy * g_verify_proxy;

void * pangu_http_ctx_new(unsigned int thread_id);

void pangu_http_ctx_free(void * pme);

size_t verify_policy_scan(enum verify_policy_type policy_type, struct verify_policy_query_obj *query_obj, cJSON *data_obj, void *pme);

void http_get_scan_status(struct verify_policy_query_obj *query_obj, cJSON *attributes, cJSON  *data_obj, void *pme);

int security_policy_init(struct verify_policy * verify, const char* profile_path);

#endif
