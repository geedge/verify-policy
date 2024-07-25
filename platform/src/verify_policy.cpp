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

#include "verify_policy.h"
#include <MESA/MESA_prof_load.h>
#include "verify_policy_utils.h"

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

int tsg_policy_type_str2idx(const char *action_str)
{
	const char * policy_name[__SCAN_POLICY_MAX];
	policy_name[TSG_TABLE_SECURITY] = "security";
	policy_name[PXY_TABLE_MANIPULATION] = "pxy_manipulation";
	policy_name[TSG_TRAFFIC_SHAPING] = "traffic_shaping";
	policy_name[TSG_SERVICE_CHAINGNG] = "service_chaining";
	policy_name[PXY_TABLE_INTERCEPT] = "pxy_intercept";
	policy_name[TSG_STATISTICS] = "statistics";
	policy_name[TSG_MONITOR] = "monitor";
	policy_name[DOS_PROTECTION] = "dos_protection";
	policy_name[PXY_TABLE_DEFENCE] = "active_defence";

	size_t i = 0;

	for (i = 0; i < sizeof(policy_name) / sizeof(const char *); i++)
	{
		if (0 == strcasecmp(action_str, policy_name[i]))
			break;
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] policyType= %s", action_str);
	return i;
}

int protoco_field_type_str2idx(const char *action_str, char *buff, char **p)
{
	const char * table_name[__TSG_OBJ_MAX] ={0};

	table_name[TSG_OBJ_SOURCE_ADDR] = "ATTR_SOURCE_IP";
	table_name[TSG_OBJ_DESTINATION_ADDR]="ATTR_DESTINATION_IP";
	table_name[TSG_OBJ_SUBSCRIBE_ID] = "ATTR_SUBSCRIBER_ID";
	table_name[TSG_OBJ_APP_ID] = "ATTR_APP_ID";
	table_name[TSG_OBJ_HTTP_URL] = "ATTR_HTTP_URL";
	table_name[TSG_OBJ_HTTP_REQ_HDR] = "ATTR_HTTP_REQ_HDR";
	table_name[TSG_OBJ_HTTP_REQ_BODY] = "ATTR_HTTP_REQ_BODY";
	table_name[TSG_OBJ_HTTP_RES_HDR] = "ATTR_HTTP_RES_HDR";
	table_name[TSG_OBJ_HTTP_RES_BODY] = "ATTR_HTTP_RES_BODY";
	table_name[TSG_OBJ_SSL_CN] = "ATTR_SSL_CN";
	table_name[TSG_OBJ_SSL_SAN] = "ATTR_SSL_SAN";
	table_name[TSG_OBJ_DOH_QNAME]="ATTR_DOH_QNAME";
	table_name[TSG_OBJ_DNS_QNAME] = "ATTR_DNS_QNAME";
	table_name[TSG_OBJ_MAIL_ACCOUNT] = "ATTR_MAIL_ACCOUNT";
	table_name[TSG_OBJ_MAIL_FROM] = "ATTR_MAIL_FROM";
	table_name[TSG_OBJ_MAIL_TO] = "ATTR_MAIL_TO";
	table_name[TSG_OBJ_MAIL_SUBJECT] = "ATTR_MAIL_SUBJECT";
	table_name[TSG_OBJ_MAIL_CONTENT] = "ATTR_MAIL_CONTENT";
	table_name[TSG_OBJ_MAIL_ATT_NAME] = "ATTR_MAIL_ATT_NAME";
	table_name[TSG_OBJ_MAIL_ATT_CONTENT] = "ATTR_MAIL_ATT_CONTENT";
	table_name[TSG_OBJ_FTP_URI] = "ATTR_FTP_URI";
	table_name[TSG_OBJ_FTP_CONTENT] = "ATTR_FTP_CONTENT";
	table_name[TSG_OBJ_FTP_ACCOUNT] = "ATTR_FTP_ACCOUNT";
	table_name[TSG_OBJ_SIP_FROM]="ATTR_SIP_ORIGINATOR_DESCRIPTION";
	table_name[TSG_OBJ_SIP_TO]="ATTR_SIP_RESPONDER_DESCRIPTION";
	table_name[TSG_OBJ_IMSI]="ATTR_GTP_IMSI";
	table_name[TSG_OBJ_PHONE_NUMBER]="ATTR_GTP_PHONE_NUMBER";
	table_name[TSG_OBJ_APN]="ATTR_GTP_APN";
	table_name[TSG_OBJ_TUNNEL]="ATTR_TUNNEL",
	table_name[TSG_OBJ_FLAG]="ATTR_FLAG";
	table_name[TSG_OBJ_GTP_IMEI]="ATTR_GTP_IMEI";
	table_name[TSG_OBJ_DST_SERVER_FQDN]="ATTR_SERVER_FQDN";
	table_name[TSG_OBJ_INTERNAL_ADDR]="ATTR_INTERNAL_IP";
	table_name[TSG_OBJ_EXTERNAL_ADDR]="ATTR_EXTERNAL_IP";
	table_name[TSG_OBJ_SOURCE_PORT]="ATTR_SOURCE_PORT";
	table_name[TSG_OBJ_DESTINATION_PORT]="ATTR_DESTINATION_PORT";
	table_name[TSG_OBJ_INTERNAL_PORT]="ATTR_INTERNAL_PORT";
	table_name[TSG_OBJ_EXTERNAL_PORT]="ATTR_EXTERNAL_PORT";
	table_name[TSG_OBJ_IP_PROTOCOL]="ATTR_IP_PROTOCOL";
	table_name[TSG_OBJ_SSL_ECH]="ATTR_SSL_ECH";
	table_name[TSG_OBJ_SSL_ESNI]="ATTR_SSL_ESNI";
	table_name[TSG_OBJ_SSL_NO_SNI]="ATTR_SSL_NO_SNI";
	table_name[TSG_OBJ_TUNNEL_LEVEL]="ATTR_TUNNEL_LEVEL";
	table_name[TSG_OBJ_TUNNEL_GTP_ENDPOINT]="ATTR_TUNNEL_GTP_ENDPOINT";
	table_name[TSG_OBJ_TUNNEL_GRE_ENDPOINT]="ATTR_TUNNEL_GRE_ENDPOINT";
	table_name[TSG_OBJ_TUNNEL_IP_IN_IP_ENDPOINT]="ATTR_TUNNEL_IP_IN_IP_ENDPOINT";

	size_t i = 0;
	for (i = 0; i < __TSG_OBJ_MAX; i++)
	{
		if (0 == strcasecmp(action_str, table_name[i]))
			break;
	}
	*p += snprintf(*p, sizeof(buff) - (*p - buff), ", protocolField=%s,%d",action_str, (int)i);

	return i;
}

int match_ip_attribute_name(char *attri_name)
{
	size_t i = 0;
	const char *attribute_name_map[] ={"source", "destination", "tunnel_endpointa", "tunnel_endpointb", "internal", "external"};
	for(i = 0; i < sizeof(attribute_name_map)/sizeof(attribute_name_map[0]); i++)
	{
		if(0 == strcasecmp(attri_name, attribute_name_map[i]))
		{
			return i;
		}
	}
	return -1;
}

struct ipaddr *ip_to_stream_addr(const char *clientIp1, unsigned int clientPort1, const char *serverIp1, unsigned int serverPort1, int addr_type, char *buff, int *protocol)
{
	struct ipaddr *ip_addr = ALLOC(struct ipaddr, 1);
	if(addr_type == 4)
	{
		struct stream_tuple4_v4 *v4_addr = ALLOC(struct stream_tuple4_v4, 1);
		ip_addr->addrtype=ADDR_TYPE_IPV4;
		inet_pton(AF_INET,clientIp1,&(v4_addr->saddr));
		v4_addr->source=clientPort1;
		inet_pton(AF_INET,serverIp1,&(v4_addr->daddr));
		v4_addr->dest=serverPort1;
		ip_addr->v4=v4_addr;
	}
	if(addr_type == 6)
	{
		struct stream_tuple4_v6 *v6_addr = ALLOC(struct stream_tuple4_v6, 1);
		ip_addr->addrtype=ADDR_TYPE_IPV6;
		inet_pton(AF_INET6,clientIp1,&(v6_addr->saddr));
		v6_addr->source=clientPort1;
		inet_pton(AF_INET6,serverIp1,&(v6_addr->daddr));
		v6_addr->dest=serverPort1;
		ip_addr->v6=v6_addr;
	}
	if(buff != NULL)
	{
		log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] %s, clientIp1=%s, clientPort1=%d, serverIp=%s, serverPort=%d, addr_type=%d, protocol=%d", buff,
				 clientIp1, clientPort1, serverIp1, serverPort1, addr_type, *protocol);
	}
	else
	{
		log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] Ip=%s, Port=%d, addr_type=%d", clientIp1, clientPort1, addr_type);
	}
	return ip_addr;
}

struct ipaddr *tunnel_to_stream_addr(const char *Ip, int addr_type)
{
	struct ipaddr *ip_addr = ALLOC(struct ipaddr, 1);
	if(addr_type == 4)
	{
		struct stream_tuple4_v4 *v4_addr = ALLOC(struct stream_tuple4_v4, 1);
		ip_addr->addrtype=ADDR_TYPE_IPV4;
		inet_pton(AF_INET,Ip,&(v4_addr->saddr));
		ip_addr->v4=v4_addr;
	}
	if(addr_type == 6)
	{
		struct stream_tuple4_v6 *v6_addr = ALLOC(struct stream_tuple4_v6, 1);
		ip_addr->addrtype=ADDR_TYPE_IPV6;
		inet_pton(AF_INET6,Ip,&(v6_addr->saddr));
		ip_addr->v6=v6_addr;
	}
	log_debug(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I]    attribute_name = ip, clientIp1=%s, addr_type = %d", Ip, addr_type);

	return ip_addr;
}

void ipaddr_free(struct ipaddr *ip_addr)
{
	if(ip_addr==NULL)
	{
		return;
	}
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

static struct ipaddr * get_ip_from_json(cJSON *attributeValue, const char *attributeName, int *protocol, char *buff)
{
	cJSON* item = NULL;
	int addr_type=0;
	const char *Ip=NULL;
	unsigned int Port=0;

	if(attributeName==NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "The attribute_type is of type iP, but the attribute_name is empty, resulting in IP type parsing failure.");
		return NULL;
	}

	item = cJSON_GetObjectItem(attributeValue,"ip");
	if(item && item->type==cJSON_String) Ip = item->valuestring;
	item = cJSON_GetObjectItem(attributeValue,"port");
	if(item && item->type==cJSON_String) Port =atoi(item->valuestring);
	item = cJSON_GetObjectItem(attributeValue,"protocol");
	if(item && item->type==cJSON_Number) *protocol = item->valueint;
	item=cJSON_GetObjectItem(attributeValue,"addr_type");
	if(item && item->type==cJSON_Number) addr_type = item->valueint;

	if(strcasecmp(attributeName, "ip_protocol") == 0)
	{
		log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] %s, protocol=%d", buff, *protocol);
		return NULL;
	}

	struct ipaddr *ip_addr = NULL;
	if(strcasecmp(attributeName, "source") == 0 || strcasecmp(attributeName, "internal") == 0 ||
	   strcasecmp(attributeName, "tunnel_endpointa") == 0 || strcasecmp(attributeName, "tunnel_endpointb") == 0)
	{
		ip_addr = ip_to_stream_addr(Ip, Port, "0.0.0.0", 0, addr_type, buff, protocol);
	}

	if(strcasecmp(attributeName, "destination") == 0 || strcasecmp(attributeName, "external") == 0)
	{
		ip_addr = ip_to_stream_addr("0.0.0.0", 0, Ip, Port, addr_type, buff, protocol);
	}
	return ip_addr;
}

static char* get_port_from_json(cJSON *attributeValue, int *protocol, char *buff)
{
	cJSON* item = NULL;
	char *string=NULL;

	item = cJSON_GetObjectItem(attributeValue,"port");
	if(item && item->type==cJSON_String)
	{
		string = item->valuestring;
	}
	item = cJSON_GetObjectItem(attributeValue,"protocol");
	if(item && item->type==cJSON_Number)
	{
		*protocol = item->valueint;
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] %s, port=%s, protocol=%d", buff, string, *protocol);

	return string;
}

static inline int match_attributeType_in_numeric(const char *attribute_type, int table_id)
{
	if(0 == strcasecmp(attribute_type, "numeric") || 0 == strcasecmp(attribute_type, "flag") ||
	   0 == strcasecmp(attribute_type, "boolean") || table_id == TSG_OBJ_IP_PROTOCOL)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static int get_attribute_from_json(int curr_id, cJSON* subchild, struct verify_policy_query *policy_query)
{
	int xret = -1;
	const char *attribute_type=NULL;
	char buff[VERIFY_STRING_MAX*2], *p = NULL;
	cJSON* item = NULL, *attributeValue=NULL, *tunnelType_item=NULL;

	p = buff;
	item = cJSON_GetObjectItem(subchild, "attribute_type");
	if(item && item->type==cJSON_String)
	{
		attribute_type = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), "attribute_type = %s", attribute_type);
	}

	item = cJSON_GetObjectItem(subchild, "attribute_name");
	if(item && item->type==cJSON_String)
	{
		policy_query->request_object[curr_id].attri_name = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", attribute_name = %s",policy_query->request_object[curr_id].attri_name);
	}
	policy_query->request_object[curr_id].attributes=cJSON_Duplicate(subchild, 1);

	item = cJSON_GetObjectItem(subchild, "table_name");
	if(item && item->type==cJSON_String)
	{
		policy_query->request_object[curr_id].table_id = protoco_field_type_str2idx(item->valuestring, buff, &p);
		if(policy_query->request_object[curr_id].table_id == __TSG_OBJ_MAX)
		{
			log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Get table id failed form table name:%s", item->valuestring);
			return xret;
		}
	}

	attributeValue = cJSON_GetObjectItem(subchild, "atrribute_value");
	if(attributeValue == NULL || attributeValue->type!=cJSON_Object)
	{
		goto finish;
	}

	tunnelType_item = cJSON_GetObjectItem(attributeValue,"tunnel_type");
	if(tunnelType_item && tunnelType_item->type==cJSON_String)
	{
		policy_query->request_object[curr_id].tunnel_type=tunnelType_item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", tunnel_type=%s",policy_query->request_object[curr_id].tunnel_type);
	}

	if(0 == strcasecmp(attribute_type, "ip"))
	{
		policy_query->request_object[curr_id].ip_addr = get_ip_from_json(attributeValue, policy_query->request_object[curr_id].attri_name, &(policy_query->request_object[curr_id].numeric), buff);
		goto end;
	}
	if(0 == strcasecmp(attribute_type, "port"))
	{
		policy_query->request_object[curr_id].string = get_port_from_json(attributeValue, &(policy_query->request_object[curr_id].numeric), buff);
		goto end;
	}

	item = cJSON_GetObjectItem(attributeValue,"district");
	if(item!=NULL)
	{
		policy_query->request_object[curr_id].district = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", district = %s",policy_query->request_object[curr_id].district);
	}

	if(match_attributeType_in_numeric(attribute_type, policy_query->request_object[curr_id].table_id))
	{
		item = cJSON_GetObjectItem(attributeValue, "numeric");
		if(item && item->type==cJSON_Number)
		{
			policy_query->request_object[curr_id].numeric = item->valueint;
			p += snprintf(p, sizeof(buff) - (p - buff), ", content = %d", policy_query->request_object[curr_id].numeric);
		}
	}
	else
	{
		item = cJSON_GetObjectItem(attributeValue, "string");
		if(item!=NULL)
		{
			policy_query->request_object[curr_id].string = item->valuestring;
			p += snprintf(p, sizeof(buff) - (p - buff), ", content = %s",policy_query->request_object[curr_id].string);
		}
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] %s", buff);
	memset(buff, 0, VERIFY_STRING_MAX*2);
end:
	xret = 1;
finish:
	return xret;
}

enum verify_type get_verify_type(cJSON* http_respone)
{
	cJSON *item = NULL;
	enum verify_type type = VERIFY_TYPE_POLICY;

	item = cJSON_GetObjectItem(http_respone,"verify_type");
	if(item && item->type==cJSON_String)
	{
		if(0 == strcasecmp(item->valuestring, "policy"))
		{
			type = VERIFY_TYPE_POLICY;
		}

		if(0 == strcasecmp(item->valuestring, "regex"))
		{
			type = VERIFY_TYPE_REGEX;
		}
		log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] verify_type= %s", item->valuestring);
	}
	return type;
}

static int get_query_result_regex(cJSON *verifylist_array_item, cJSON *http_body)
{
	int cur_id=0, i=0, is_valid[32]={0};
	cJSON *regexstr_obj[32],*attributes=NULL;
	cJSON *item = NULL, *subchild = NULL;

	attributes = cJSON_GetObjectItem(verifylist_array_item, "verify_regex");
	if(attributes==NULL || attributes->type != cJSON_Array)
	{
		return -1;
	}

	for (subchild = attributes->child; subchild != NULL; subchild = subchild->next)
	{
		item = cJSON_GetObjectItem(subchild, "regex_str");
		if(item && item->type==cJSON_String)
		{
			is_valid[cur_id] = policy_verify_regex_expression(item->valuestring);
		}
		regexstr_obj[cur_id]=cJSON_Duplicate(item, 1);
		cur_id++;
	}

	cJSON *verify_regex_obj=NULL;

	cJSON *verifyRegex=cJSON_CreateArray();
	cJSON_AddItemToObject(http_body, "verify_regex", verifyRegex);
	for (i = 0; i < cur_id; i++)
	{
		verify_regex_obj=cJSON_CreateObject();
		cJSON_AddItemToObject(verify_regex_obj, "regex_str", regexstr_obj[i]);
		cJSON_AddNumberToObject(verify_regex_obj, "is_valid", is_valid[i]);
		cJSON_AddItemToArray(verifyRegex, verify_regex_obj);
	}
	return 1;
}

static void get_count_form_attributeName(void *ctx, cJSON *subchild)
{
	cJSON *item = NULL;

	item = cJSON_GetObjectItem(subchild, "attribute_name");
	if(item && item->type==cJSON_String)
	{
		if(0 == strcasecmp(item->valuestring, "tunnel_endpointa"))
		{
			verify_policy_tunnle_add(ctx);
		}
		if(0 == strcasecmp(item->valuestring, "tunnel_endpointb"))
		{
			verify_policy_tunnle_add(ctx);
		}
	}
	return;
}

int get_query_result_policy(cJSON *verifylist_array_item, cJSON *http_body, int thread_id)
{
	int attribute_num = 0;
	int hit_cnt = 0, xret =0;
	cJSON *item = NULL, *subchild = NULL, *attributes=NULL;
	struct verify_policy_query *verify_policy = NULL;

	verify_policy = ALLOC(struct verify_policy_query, 1);
	item = cJSON_GetObjectItem(verifylist_array_item,"type");
	if(item && item->type==cJSON_String)
	{
		verify_policy->compile_table_id = tsg_policy_type_str2idx(item->valuestring);
		if (verify_policy->compile_table_id >= __SCAN_POLICY_MAX)
		{
			log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "policy type error, policy id = %d", verify_policy->compile_table_id);
			goto free;
		}
	}

	item = cJSON_GetObjectItem(verifylist_array_item, "vsys_id");
	if(item && item->type==cJSON_Number)
	{
		verify_policy->vsys_id = item->valueint;
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] vsys_id= %d", verify_policy->vsys_id);

	item = cJSON_GetObjectItem(verifylist_array_item,"verify_session");
	if(item == NULL || item->type!=cJSON_Object)
	{
		goto free;
	}

	attributes = cJSON_GetObjectItem(item,"attributes");
	if(attributes && attributes->type==cJSON_Array)
	{
		void *ctx = policy_scan_ctx_new(thread_id, verify_policy->vsys_id, verify_policy->compile_table_id);

		for (subchild = attributes->child; subchild != NULL; subchild = subchild->next)
		{
			get_count_form_attributeName(ctx, subchild);
		}

		for (subchild = attributes->child; subchild != NULL; subchild = subchild->next)
		{
			xret = get_attribute_from_json(attribute_num, subchild, verify_policy);
			if (xret < 0)
			{
				goto free;
			}
			hit_cnt = policy_verify_scan(verify_policy->vsys_id, verify_policy->compile_table_id, &verify_policy->request_object[attribute_num], ctx);
			if(match_ip_attribute_name(verify_policy->request_object[attribute_num].attri_name) >= 0)
			{
				ipaddr_free(verify_policy->request_object[attribute_num].ip_addr);
			}
			attribute_num++;
		}
		http_hit_policy_list(verify_policy, attribute_num, hit_cnt, http_body, ctx);

		int item = 0;
		cJSON *verfifySession = cJSON_CreateObject();
		cJSON_AddItemToObject(http_body, "verify_session", verfifySession);
		cJSON *attributes=cJSON_CreateArray();
		cJSON_AddItemToObject(verfifySession, "attributes", attributes);
		for (item = 0; item < attribute_num; item++)
		{
			http_get_scan_status(&verify_policy->request_object[item], verify_policy->compile_table_id, attributes, http_body, ctx);
		}
		policy_scan_ctx_free(ctx);
	}

	attribute_num=0;
free:
	if (verify_policy)
	{
		FREE(&verify_policy);
	}

	return hit_cnt;
}

cJSON *get_verify_policy_query(const char *data, ssize_t data_len, int thread_id)
{
	int hit_cnt = 0;

	cJSON* http_request = cJSON_Parse(data);
	if(http_request == NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Failed to parse the request data.");
		return NULL;
	}
	cJSON  *http_respone=NULL, *http_body=NULL;
	http_respone=cJSON_CreateObject();

	cJSON_AddNumberToObject(http_respone, "code", 200);
	cJSON_AddStringToObject(http_respone, "msg", "Success");

	http_body = cJSON_CreateObject();
	cJSON_AddItemToObject(http_respone, "data", http_body);

	int type=get_verify_type(http_request);
	cJSON *item = NULL, *subitem = NULL;

	item = cJSON_GetObjectItem(http_request,"verify_list");
	if(item && item->type==cJSON_Array)
	{
		for (subitem = item->child; subitem != NULL; subitem = subitem->next)
		{
			if(type == VERIFY_TYPE_REGEX)
			{
				log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] data= %.*s", (int)data_len, data);
				hit_cnt = get_query_result_regex(subitem, http_body);
			}

			if(type == VERIFY_TYPE_POLICY)
			{
				hit_cnt = get_query_result_policy(subitem, http_body, thread_id);
			}
		}
		if (hit_cnt >= 0)
		{
			cJSON_AddBoolToObject(http_respone, "success", true);
		}
		else
		{
			cJSON_AddBoolToObject(http_respone, "success", false);
		}
	}
	cJSON_Delete(http_request);
	return http_respone;
}

int http_get_headers(struct evhttp_request *evh_req, struct evkeyvalq *headers)
{
	int xret = -1;

	const char *uri = evhttp_request_get_uri(evh_req);
	if(!uri)
	{
		return xret;
	}
	return evhttp_parse_query(uri, headers);
}

int http_get_int_param(struct evhttp_request *evh_req, const char *key)
{
	int xret=-1, vsys_id=-1;
	struct evkeyvalq headers;

	xret = http_get_headers(evh_req, &headers);
	if(xret != 0)
	{
		return -1;
	}
	const char *value = evhttp_find_header(&headers, key);
	if (value)
	{
		vsys_id = atoi(value);
	}
	evhttp_clear_headers(&headers);
	return vsys_id;
}

char *http_get_string_param(struct evhttp_request *evh_req, const char *key)
{
	int xret=-1;
	char *param=NULL;
	struct evkeyvalq headers;

	xret = http_get_headers(evh_req, &headers);
	if(xret != 0)
	{
		return NULL;
	}
	const char *value = evhttp_find_header(&headers, key);
	if (value)
	{
		param = strdup(value);
	}
	evhttp_clear_headers(&headers);
	return param;
}

int get_ip_type(const char *ip)
{
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    int addr_type = 0;

    if (inet_pton(AF_INET, ip, &(sa.sin_addr)) > 0)
	{
        addr_type = 4;
    }
	else if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr)) > 0)
	{
        addr_type = 6;
    }
    return addr_type;
}

cJSON *get_library_search_query(struct evhttp_request *evh_req)
{
	int hit_library_cnt=0;
	cJSON *http_respone=cJSON_CreateObject();
	cJSON_AddNumberToObject(http_respone, "code", 200);
	cJSON_AddStringToObject(http_respone, "msg", "Success");

	cJSON *http_body = cJSON_CreateObject();
	cJSON_AddItemToObject(http_respone, "data", http_body);

	cJSON *hit_library=cJSON_CreateArray();
	cJSON_AddItemToObject(http_body, "hit_library", hit_library);

	int vsys_id = http_get_int_param(evh_req, "vsys_id");
	if(vsys_id < 0)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "invalid vsys_id");
		return NULL;
	}

	char *ip = http_get_string_param(evh_req, "ip");
	if(ip) 
	{
		struct ipaddr *ip_addr = ip_to_stream_addr(ip, 0, "0.0.0.0", 0, get_ip_type(ip), NULL, 0);
		hit_library_cnt=get_ip_entry_tag_ids(hit_library, vsys_id, ip_addr);
		FREE(&ip);
		ipaddr_free(ip_addr);
	}
	
	char *fqdn = http_get_string_param(evh_req, "fqdn");
	if(fqdn)
	{
		hit_library_cnt=get_fqdn_entry_tag_ids(hit_library, vsys_id, fqdn);
		FREE(&fqdn);
	}

	if (hit_library_cnt > 0)
	{
		cJSON_AddBoolToObject(http_body, "success", true);
	}
	else
	{
		cJSON_AddBoolToObject(http_body, "success", false);
	}
	return http_respone;
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
	char *http_payload_string= NULL; cJSON  *http_payload=NULL;

	if (evhttp_request_get_command(evh_req) != EVHTTP_REQ_POST)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "FAILED (post type)");
		goto error;
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] Request library search: %s", evhttp_request_get_uri(evh_req));

	http_payload = get_library_search_query(evh_req);
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

	evhttp_set_cb(thread->http, "/v1/policy/trouble_shooting/policy_verification", verify_policy_request_cb, thread);
	evhttp_set_cb(thread->http, "/v1/policy/trouble_shooting/library_search", library_search_request_cb, thread);

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
    int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;

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
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "breakpad_upload_url is necessary, failed. ");
		goto errout;
	}

	ret = readlink("/proc/self/exe", execpath, sizeof(execpath));
	if(unlikely(ret < 0))
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Failed at readlink /proc/self/exec: %s", strerror(errno));
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
			log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "setrlimit(RLIMIT_CORE, 0) failed: %s", strerror(errno));
			/* after log, reset errno */
			errno = 0;
		}
	}

	MESA_load_profile_uint_def(profile, "system", "enable_breakpad", &instance->en_breakpad, 1);
	if (instance->en_breakpad <= 0)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Breakpad Crash Reporting System is disabled. ");
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
			log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Breakpad upload init failed, using local breakpad dumpfile");
			instance->en_breakpad_upload = 0;
		}

		/* When we use breakpad, do not generate any coredump file */
		const struct rlimit __rlimit_vars = {.rlim_cur = 0, .rlim_max = 0};
		ret = setrlimit(RLIMIT_CORE, &__rlimit_vars);
		if (ret < 0)
		{
			log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "setrlimit(RLIMIT_CORE, 0) failed: %s", strerror(errno));
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
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Breakpad Crash Report is enable. ");
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Minidump Dir: %s", instance->minidump_dir_prefix);
	return instance;
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

	const char *log_path="./logs/verify_policy.log";
	MESA_load_profile_int_def(main_profile, "SYSTEM", "log_level", &log_level, LOG_FATAL);
	g_verify_proxy->logger = log_handle_create(log_path, log_level);
	CHECK_OR_EXIT(g_verify_proxy->logger != NULL, "Failed at init log module. Exit.");

	ret = load_system_conf(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at loading profile %s, Exit.", main_profile);

	clock_gettime(CLOCK_REALTIME, &(start_time));
	ret = maat_table_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at init maat module, Exit.");
	clock_gettime(CLOCK_REALTIME, &(end_time));

	log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Read table_info.conf, take time %lu(s)", end_time.tv_sec - start_time.tv_sec);
	printf("Read table_info.conf, take time %lu(s)\n", end_time.tv_sec - start_time.tv_sec);

	g_verify_proxy->breakpad = breakpad_init(main_profile);
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

