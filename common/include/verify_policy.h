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

enum scan_table
{
	PXY_CTRL_IP,
	PXY_CTRL_HTTP_URL,
	PXY_CTRL_HTTP_FQDN,
	PXY_CTRL_HTTP_REQ_HDR,
	PXY_CTRL_HTTP_REQ_BODY,
	PXY_CTRL_HTTP_RES_HDR,
	PXY_CTRL_HTTP_RES_BODY,
	PXY_CTRL_SUBSCRIBE_ID,
	__SCAN_TABLE_MAX
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

struct verify_proxy_thread
{
	int  id;
	pthread_t pid;        
	evutil_socket_t accept_fd;
	pthread_attr_t *attr;	
	struct evhttp *http;
	struct event_base *base;
	void * (*routine)(void *);  
};

struct verify_proxy
{	
	char name[VERIFY_SYMBOL_MAX];		
	void * logger;
	unsigned int log_level;
	unsigned int nr_work_threads;
	unsigned int listen_port;	
	struct verify_proxy_thread *work_threads[TFE_THREAD_MAX];
};

extern struct verify_proxy * g_verify_proxy;

void * pangu_http_ctx_new(unsigned int thread_id);

void http_scan(const char * value, enum tfe_http_event events,
	const unsigned char * body_frag, size_t frag_size, void *pme);

char *web_json_table_add(void *pme);

#endif
