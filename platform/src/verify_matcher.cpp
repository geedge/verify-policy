/*************************************************************************
	> File Name: policy_scan.cpp
	> Author:
	> Mail:
	> Created Time: 2019年08月23日 星期五 16时53分25秒
 ************************************************************************/
#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <MESA/maat.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/stream.h>

#include <uuid/uuid.h>
#include <cjson/cJSON.h>

#include "utils.h"
#include "utarray.h"
#include "verify_policy.h"

#define MAX_EX_DATA_LEN 			16
#define HIT_PATH_SIZE           	1024
#define	MAX_SCAN_RESULT				16
#define MAX_REGEX_EXPRESS_NUM       32
#define MERGE_SCAN_NTH 				128

#define	MODULE_VERIFY_MATCHER "verify-policy.matcher"

const char * table_name[__TSG_OBJ_MAX] =
{
	[TSG_OBJ_SOURCE_ADDR] = "ATTR_SOURCE_IP",
	[TSG_OBJ_DESTINATION_ADDR]="ATTR_DESTINATION_IP",
	[TSG_OBJ_SUBSCRIBE_ID] = "ATTR_SUBSCRIBER_ID",
	[TSG_OBJ_APP_ID] = "ATTR_APP_ID",
	[TSG_OBJ_HTTP_URL] = "ATTR_HTTP_URL",
	[TSG_OBJ_HTTP_REQ_HDR] = "ATTR_HTTP_REQ_HDR",
	[TSG_OBJ_HTTP_REQ_BODY] = "ATTR_HTTP_REQ_BODY",
	[TSG_OBJ_HTTP_RES_HDR] = "ATTR_HTTP_RES_HDR",
	[TSG_OBJ_HTTP_RES_BODY] = "ATTR_HTTP_RES_BODY",
	[TSG_OBJ_SSL_CN] = "ATTR_SSL_CN",
	[TSG_OBJ_SSL_SAN] = "ATTR_SSL_SAN",
	[TSG_OBJ_DOH_QNAME]="ATTR_DOH_QNAME",
	[TSG_OBJ_DNS_QNAME] = "ATTR_DNS_QNAME",
	[TSG_OBJ_MAIL_ACCOUNT] = "ATTR_MAIL_ACCOUNT",
	[TSG_OBJ_MAIL_FROM] = "ATTR_MAIL_FROM",
	[TSG_OBJ_MAIL_TO] = "ATTR_MAIL_TO",
	[TSG_OBJ_MAIL_SUBJECT] = "ATTR_MAIL_SUBJECT",
	[TSG_OBJ_MAIL_CONTENT] = "ATTR_MAIL_CONTENT",
	[TSG_OBJ_MAIL_ATT_NAME] = "ATTR_MAIL_ATT_NAME",
	[TSG_OBJ_MAIL_ATT_CONTENT] = "ATTR_MAIL_ATT_CONTENT",
	[TSG_OBJ_FTP_URI] = "ATTR_FTP_URI",
	[TSG_OBJ_FTP_CONTENT] = "ATTR_FTP_CONTENT",
	[TSG_OBJ_FTP_ACCOUNT] = "ATTR_FTP_ACCOUNT",
	[TSG_OBJ_SIP_FROM]="ATTR_SIP_ORIGINATOR_DESCRIPTION",
	[TSG_OBJ_SIP_TO]="ATTR_SIP_RESPONDER_DESCRIPTION",
	[TSG_OBJ_IMSI]="ATTR_GTP_IMSI",
	[TSG_OBJ_PHONE_NUMBER]="ATTR_GTP_PHONE_NUMBER",
	[TSG_OBJ_APN]="ATTR_GTP_APN",
	[TSG_OBJ_TUNNEL]="ATTR_TUNNEL",
	[TSG_OBJ_FLAG]="ATTR_FLAG",
	[TSG_OBJ_GTP_IMEI]="ATTR_GTP_IMEI",
	[TSG_OBJ_DST_SERVER_FQDN]="ATTR_SERVER_FQDN",
	[TSG_OBJ_INTERNAL_ADDR]="ATTR_INTERNAL_IP",
	[TSG_OBJ_EXTERNAL_ADDR]="ATTR_EXTERNAL_IP",
	[TSG_OBJ_SOURCE_PORT]="ATTR_SOURCE_PORT",
	[TSG_OBJ_DESTINATION_PORT]="ATTR_DESTINATION_PORT",
	[TSG_OBJ_INTERNAL_PORT]="ATTR_INTERNAL_PORT",
	[TSG_OBJ_EXTERNAL_PORT]="ATTR_EXTERNAL_PORT",
	[TSG_OBJ_IP_PROTOCOL]="ATTR_IP_PROTOCOL",
	[TSG_OBJ_SSL_ECH]="ATTR_SSL_ECH",
	[TSG_OBJ_SSL_ESNI]="ATTR_SSL_ESNI",
	[TSG_OBJ_SSL_NO_SNI]="ATTR_SSL_NO_SNI",
	[TSG_OBJ_TUNNEL_LEVEL]="ATTR_TUNNEL_LEVEL",
	[TSG_OBJ_TUNNEL_GTP_ENDPOINT]="ATTR_TUNNEL_GTP_ENDPOINT",
	[TSG_OBJ_TUNNEL_GRE_ENDPOINT]="ATTR_TUNNEL_GRE_ENDPOINT",
	[TSG_OBJ_TUNNEL_IP_IN_IP_ENDPOINT]="ATTR_TUNNEL_IP_IN_IP_ENDPOINT"
};

enum policy_action
{
	PG_ACTION_NONE = 0,
	PG_ACTION_MONIT = 1,
	PG_ACTION_INTERCEPT = 2,    /* N/A */
	PG_ACTION_NO_INTERCEPT = 3,
	PG_ACTION_ACTIVE_DEFENCE = 4,
	PG_ACTION_WANNAT = 8,
	PG_ACTION_REJECT = 16,
	PG_ACTION_SHAPING = 32,
	PG_ACTION_MANIPULATE = 48,
	PG_ACTION_SERVICE_CHAINING=64,
	PG_ACTION_WHITELIST = 96,
	PX_ACTION_SHUNT = 128,
	PG_STATISTICS = 129,
	__PG_ACTION_MAX
};

enum http_std_field
{
	HTTP_UNKNOWN_FIELD = 0,
	HTTP_USER_AGENT,
	HTTP_COOKIE,
	HTTP_SET_COOKIE,
	HTTP_CONT_TYPE,
};

enum verify_profile_table
{
	PROFILE_APP_DI_DICT,
	PROFILE_FQDN_ENTRY,
	PROFILE_IP_ADDR_ENTRY,
	PROFILE_LIBRARY_TAG,
	PROFILE_ATTRIBUTE_DICT,
	PROFILE_TABLE_MAX,
};

struct http_field_name
{
	const char * field_name;
	enum http_std_field field_id;
};

/** Nth_scan: Since there is no virtual table name in the request due to IP location and IP protocol,
 * the current hit path scan count needs to be recorded to correspond to the virtual table name */
struct library_tag_entry
{
	char *uuid;
	char *tag_uuid;
	int category;
};

struct library_hit_path
{
	int table_id;
	int entry_num;

	int Nth_scan_num;
	int Nth_scan[MAX_TAG_ID_NUM];

	struct library_tag_entry tag[MAX_TAG_ID_NUM];
};

struct library_scan_path
{
	int ut_array_cnt;
	UT_array *ut_array_by_context;
};

struct rule_data_ctx
{
	int     ref_cnt;
	int		service_id;
	unsigned char action;
	uuid_t rule_uuid;
	pthread_mutex_t lock;
};

struct app_id_dict
{
	int ref_cnt;
	int app_id;
	uuid_t object_uuid;
	pthread_mutex_t lock;
};

enum statistics_option_type
{
	STATISTICS_OPTION_NONE=0,
	STATISTICS_OPTION_BRIEF,
	STATISTICS_OPTION_ELABORATE,
	STATISTICS_OPTION_MAX
};

enum category_type
{
	CATEGORY_TYPE_UNKNOWN = 0,
	CATEGORY_TYPE_GEOIP,
	CATEGORY_TYPE_CONTRY_CODE,
	CATEGORY_TYPE_ASN,
	CATEGORY_TYPE_WEBSITE_CATEGORY,
	CATEGORY_TYPE_INTERNET_SERVICE,
	CATEGORY_TYPE_SECURITY_THREAT,
	CATEGORY_TYPE_RISK,
	CATEGORY_TYPE_MAX
};

struct library_entry_ctx
{
	int ref_cnt;
	char *uuid;
	int n_tag_uuids;
	char *tag_uuids;
	char *tag_uuid_array[MAX_TAG_ID_NUM];

	pthread_mutex_t lock;
};

struct library_tag_ctx
{
	int ref_cnt;
	char *uuid;
	char *tag_key;
	char *tag_value;
	enum category_type category;
	enum statistics_option_type option_type;

	pthread_mutex_t lock;
};

struct attribute_dict_ctx
{
	int ref_cnt;
	char *attribute_name;
	char *object_table_name;
	char *available_object_type;

	pthread_mutex_t lock;
};

struct policy_scan_ctx
{
	int n_read;
    int thread_id;
    enum policy_action action;
    struct maat_state *scan_mid;
    struct maat_state *tunnel_scan_mid;
    size_t hit_cnt;
    struct rule_data_ctx *hit_rules;
    struct maat_hit_path hit_path[HIT_PATH_SIZE];
    size_t n_enforce;
    struct rule_data_ctx *enforce_rules;
    int tunnel_attr_count;
	uuid_t result[MAX_SCAN_RESULT];
    struct library_scan_path scan_path;
};

struct request_object_list
{
    int table_id;
    int numeric;
    int merge_nth_scan_num;
    int merge_nth_scan[MERGE_SCAN_NTH];
    char *string;
	char *tunnel_type;
    char *district_value;
    char *attribute_name;
    struct ipaddr *ip_addr;
    cJSON *attributes;
};

struct verify_policy_query
{
    int vsys_id;
	int compile_table_id;
    int ut_array_cnt;
    UT_array *ut_array_by_object;
};

struct verify_policy_rt
{
	int log_level;
	int thread_num;
	int load_library;
	int hit_path_size;
	int compile_table_id[__SCAN_POLICY_MAX];
	int plugin_table_id[__SCAN_POLICY_MAX];
	int profile_table_id  [PROFILE_TABLE_MAX];
	int scan_table_id[__TSG_OBJ_MAX];
	struct maat *feather[VSYS_ID_MAX];
	struct log_handle *local_logger;
};

struct verify_policy_rt * g_policy_rt;

#define MAAT_INPUT_JSON			0
#define MAAT_INPUT_REDIS    	1
#define MAAT_INPUT_FILE        	2

#define BOOLEAN_TRUE_OBJECT_UUID 	"00000000-0000-0000-0000-000000000002"
#define BOOLEAN_FLASE_OBJECT_UUID	"00000000-0000-0000-0000-000000000003"
#define PROTOCOL_ANY_OBJECT_UUID 	"00000000-0000-0000-0000-000000000004"
#define PROTOCOL_ICMP_OBJECT_UUID   "00000000-0000-0000-0000-000000000005"
#define PROTOCOL_TCP_OBJECT_UUID	"00000000-0000-0000-0000-000000000006"
#define PROTOCOL_UDP_OBJECT_UUID	"00000000-0000-0000-0000-000000000007"

UT_icd ut_ulonglong_id_icd = {sizeof(struct library_hit_path), NULL, NULL, NULL};

void attribute_dict_free(struct attribute_dict_ctx *dict_ctx);

const char *get_conjunction_table_name(enum policy_rule_type rule_type)
{
	const char *conjunction_table_name_map[] = {"SECURITY_RULE_CONJUNCTION", "PXY_CTRL_RULE_CONJUNCTION", "TRAFFIC_SHAPING_RULE_CONJUNCTION",
												"SERVICE_CHAINING_RULE_CONJUNCTION", "PXY_INTERCEPT_RULE_CONJUNCTION","STATISTICS_COMPILE_CONJUNCTION",
												"MONITOR_RULE_CONJUNCTION", "DOS_PROTECTION_RULE_CONJUNCTION", "TUNNEL_RULE_CONJUNCTION"};
	size_t table_name_map_len = sizeof(conjunction_table_name_map)/sizeof(conjunction_table_name_map[0]);

	if(table_name_map_len < rule_type)
	{
		rule_type=TSG_TABLE_SECURITY;
		log_error(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "invalid policy rule type");
	}
	return conjunction_table_name_map[rule_type];
}

const char *get_plugin_table_name(enum policy_rule_type rule_type)
{
	const char *plugin_table_name_map[] = {"SECURITY_RULE_PLUGIN", "PXY_CTRL_RULE_PLUGIN", "TRAFFIC_SHAPING_RULE_PLUGIN",
											"SERVICE_CHAINING_RULE_PLUGIN", "PXY_INTERCEPT_RULE_PLUGIN", "STATISTICS_COMPILE_PLUGIN",
											"MONITOR_RULE_PLUGIN", "DOS_PROTECTION_RULE_PLUGIN", "TUNNEL_RULE_PLUGIN"};

	size_t table_name_map_len = sizeof(plugin_table_name_map)/sizeof(plugin_table_name_map[0]);

	if(table_name_map_len < rule_type)
	{
		rule_type=TSG_TABLE_SECURITY;
		log_error(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "invalid policy rule type");
	}
	return plugin_table_name_map[rule_type];
}

unsigned long long int uuid_to_int64(uuid_t uuid)
{
	unsigned long long int uuid_int = 0;
	for (int i = 0; i < 16; i++) {
        uuid_int = (uuid_int << 8) | uuid[i];
    }
    return uuid_int;
}

int cJSON_AddUuidToObject(cJSON * const object, const char * const name, uuid_t uuid)
{
	char uuid_str[UUID_STR_LEN]={0};
	uuid_unparse(uuid, uuid_str);
	cJSON_AddStringToObject(object, name, uuid_str);
	return 1;
}

char *get_table_name(char *attribute_name, int vsys_id)
{
	char *table_name=NULL;
	struct attribute_dict_ctx *dict_ctx =(struct attribute_dict_ctx *)maat_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "ATTRIBUTE_DICT", (const char *)attribute_name, strlen(attribute_name));
	if(dict_ctx != NULL)
	{
		table_name = dict_ctx->object_table_name;
		attribute_dict_free(dict_ctx);
	}
	return table_name;
}

struct policy_scan_ctx *policy_scan_ctx_new(unsigned int thread_id, int vsys_id, int compile_table_id)
{
	struct policy_scan_ctx * ctx = ALLOC(struct policy_scan_ctx, 1);
	ctx->thread_id = thread_id;
	utarray_new(ctx->scan_path.ut_array_by_context, &ut_ulonglong_id_icd);
	ctx->scan_mid = maat_state_new(g_policy_rt->feather[vsys_id], thread_id);
	maat_state_set_scan_rule_table(ctx->scan_mid, get_conjunction_table_name((enum policy_rule_type)compile_table_id));

	return ctx;
}

void policy_scan_ctx_free(struct policy_scan_ctx * ctx)
{
	if(ctx->enforce_rules)
		FREE(&ctx->enforce_rules);

	if(ctx->hit_rules)
		FREE(&ctx->hit_rules);

	maat_state_free(ctx->scan_mid);
	ctx->scan_mid = NULL;

	if(ctx->tunnel_scan_mid)
	{
		maat_state_free(ctx->tunnel_scan_mid);
		ctx->tunnel_scan_mid = NULL;
	}

	struct library_hit_path *library_entry=NULL;
	while ((library_entry=(struct library_hit_path *)utarray_next(ctx->scan_path.ut_array_by_context, library_entry)) != NULL)
	{
		if(library_entry != NULL)
		{
			for(int i=0; i < library_entry->entry_num; i++)
			{
				if(library_entry->tag[i].uuid)
				{
					free(library_entry->tag[i].uuid);
					library_entry->tag[i].uuid=NULL;
				}
				if(library_entry->tag[i].tag_uuid)
				{
					free(library_entry->tag[i].tag_uuid);
					library_entry->tag[i].tag_uuid=NULL;
				}
			}
		}

	}
	utarray_free(ctx->scan_path.ut_array_by_context);
	FREE(&ctx);
}

static int policy_action_weight[__PG_ACTION_MAX] = {0};
void __policy_action_weight_init()  __attribute__((constructor, used));
void __policy_action_weight_init()
{
	policy_action_weight[PG_ACTION_NONE] = 0;
	policy_action_weight[PG_ACTION_MONIT] = 1;
	policy_action_weight[PG_ACTION_INTERCEPT] = 2;
	policy_action_weight[PG_ACTION_NO_INTERCEPT] = 3;
	policy_action_weight[PG_ACTION_SHAPING] = 4;
	policy_action_weight[PG_ACTION_MANIPULATE] = 5;
	policy_action_weight[PG_ACTION_SERVICE_CHAINING]=6;
	policy_action_weight[PG_ACTION_REJECT] = 7;
	policy_action_weight[PG_ACTION_WHITELIST] = 8;
	policy_action_weight[PX_ACTION_SHUNT] = 9;
	policy_action_weight[PG_STATISTICS] = 10;
}

static inline int action_cmp(enum policy_action a1, enum policy_action a2)
{
	return policy_action_weight[a1] - policy_action_weight[a2];
}

#ifdef INCLUDE_UNUSED_FUNCTIONS
static char* verify_unescape(char* s)
{
	int i=0,j=0;
	int len=strlen(s);
	for(i=0,j=0;i<len;i++)
	{
		if(s[i]=='\\')
		{
			switch(s[i+1])
			{
				case '&':
					s[j]='&';
					break;
				case 'b':
					s[j]=' ';//space,0x20;
					break;
				case '\\':
					s[j]='\\';
					break;
				default:
					s[j]=s[i];
					i--;	//undo the followed i++
					break;
			}
			i++;
			j++;
		}
		else
		{
			s[j]=s[i];
			j++;
		}
	}
	s[j]='\0';
	return s;
}
#endif

const char *table_name_map[PROFILE_TABLE_MAX] =
{
	[PROFILE_APP_DI_DICT]="APP_ID_DICT",
	[PROFILE_FQDN_ENTRY]="FQDN_ENTRY",
	[PROFILE_IP_ADDR_ENTRY]="IP_ADDR_ENTRY",
	[PROFILE_LIBRARY_TAG]="LIBRARY_TAG",
	[PROFILE_ATTRIBUTE_DICT]="ATTRIBUTE_DICT"
};

int maat_plugin_table_ex_init(int profile_idx, int vsys_id,
							  maat_ex_new_func_t* new_func,
							  maat_ex_free_func_t* free_func,
							  maat_ex_dup_func_t* dup_func)
{
	const char *table_name = table_name_map[profile_idx];
	int ret=maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, new_func, free_func, dup_func, 0, NULL);
	if(ret < 0)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Register maat plugin table %s failed.", table_name);
	}
	return ret;
}

void app_dict_table_new_cb(const char *table_name, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	cJSON* app_id_dict_json = cJSON_Parse(table_line);
	if(app_id_dict_json == NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "APP_ID_DICT parse table_line failed. table_line:%s", table_line);
		return;
	}

	struct app_id_dict *app_dict=ALLOC(struct app_id_dict, 1);
	cJSON *item = cJSON_GetObjectItem(app_id_dict_json, "app_id");
	if(item && item->type==cJSON_Number)
	{
		app_dict->app_id = item->valueint;
	}

	item = cJSON_GetObjectItem(app_id_dict_json, "object_uuid");
	if(item && item->type==cJSON_String)
	{
		uuid_parse(item->valuestring, app_dict->object_uuid);
	}

	cJSON_Delete(app_id_dict_json);

	app_dict->ref_cnt=1;
	pthread_mutex_init(&(app_dict->lock), NULL);
	*ad=app_dict;
	return;
}

void app_dict_table_free_cb(const char *table_name, void **ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}

	struct app_id_dict *app_dict=(struct app_id_dict *)(*ad);
	pthread_mutex_lock(&(app_dict->lock));
	app_dict->ref_cnt--;
	if(app_dict->ref_cnt>0)
	{
		pthread_mutex_unlock(&(app_dict->lock));
		return;
	}
	pthread_mutex_unlock(&(app_dict->lock));
	pthread_mutex_destroy(&(app_dict->lock));

	FREE(&app_dict);
	*ad=NULL;
	return;
}

void app_id_dict_free(struct app_id_dict *app_dict)
{
	app_dict_table_free_cb(0, (void **)&app_dict, 0, NULL);
}

void app_dict_table_dup_cb(const char *table_name, void **to, void **from, long argl, void* argp)
{
	struct app_id_dict *app_dict=(struct app_id_dict *)(*from);
	pthread_mutex_lock(&(app_dict->lock));
	app_dict->ref_cnt++;
	pthread_mutex_unlock(&(app_dict->lock));
	*to=app_dict;

	return;
}

int get_tag_id_array(char *tag_ids, char *tag_uuid_array[])
{
	if(tag_ids==NULL)
	{
		return 0;
	}

	int n_tag_ids=0;
	char *tag_ids_tmp = ALLOC(char, strlen(tag_ids)+1);
	strcpy(tag_ids_tmp, tag_ids);

    char *tag_ids_str=strtok(tag_ids_tmp, ",");
    while(tag_ids_str!=NULL && n_tag_ids < MAX_TAG_ID_NUM)
	{
        tag_uuid_array[n_tag_ids++]=strdup(tag_ids_str);
        tag_ids_str=strtok(NULL, ",");
    }
	FREE(&tag_ids_tmp);
	return n_tag_ids;
}

void fqdn_entry_new_cb(const char *table_name, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	cJSON* fqdn_entry_json = cJSON_Parse(table_line);
	if(fqdn_entry_json == NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "FQDN_ENTRY parse table_line failed. table_line:%s", table_line);
		return;
	}

	struct library_entry_ctx *entry_ctx=ALLOC(struct library_entry_ctx, 1);
	cJSON *item = cJSON_GetObjectItem(fqdn_entry_json, "uuid");
	if(item && item->type==cJSON_String)
	{
		entry_ctx->uuid=strdup(item->valuestring);
	}

	int n_tag_ids=0;
	cJSON *tag_uuids_item = cJSON_GetObjectItem(fqdn_entry_json, "tag_uuids");
	entry_ctx->n_tag_uuids=cJSON_GetArraySize(tag_uuids_item);

	entry_ctx->tag_uuids = ALLOC(char, entry_ctx->n_tag_uuids*UUID_STR_LEN);

	if(entry_ctx->n_tag_uuids>0)
	{
		for(int i=0; i< entry_ctx->n_tag_uuids; i++)
		{
			cJSON *tag_uuids_sub=cJSON_GetArrayItem(tag_uuids_item, i);
			if(tag_uuids_sub != NULL)
			{
				entry_ctx->tag_uuid_array[n_tag_ids]=strdup(tag_uuids_sub->valuestring);
				n_tag_ids++;
			}
			strcat(entry_ctx->tag_uuids, tag_uuids_sub->valuestring);
			if (i < entry_ctx->n_tag_uuids - 1)
			{
                strcat(entry_ctx->tag_uuids, ",");
            }
		}
	}

	cJSON_Delete(fqdn_entry_json);

	entry_ctx->ref_cnt=1;
	pthread_mutex_init(&(entry_ctx->lock), NULL);
	*ad=entry_ctx;
	return;
}

void library_entry_free_cb(const char *table_name, void **ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}

	struct library_entry_ctx *entry_ctx=(struct library_entry_ctx *)(*ad);
	pthread_mutex_lock(&(entry_ctx->lock));
	entry_ctx->ref_cnt--;
	if(entry_ctx->ref_cnt>0)
	{
		pthread_mutex_unlock(&(entry_ctx->lock));
		return;
	}
	pthread_mutex_unlock(&(entry_ctx->lock));
	pthread_mutex_destroy(&(entry_ctx->lock));

	if(entry_ctx->uuid)
	{
		FREE(&entry_ctx->uuid);
	}

	if(entry_ctx->tag_uuids)
	{
		FREE(&entry_ctx->tag_uuids);
	}

	for(int i=0; i<entry_ctx->n_tag_uuids; i++)
	{
		if(entry_ctx->tag_uuid_array[i])
		{
			FREE(&entry_ctx->tag_uuid_array[i]);
		}
	}
	FREE(&entry_ctx);
	*ad=NULL;
	return;
}

void library_entry_free(struct library_entry_ctx *entry_ctx)
{
	library_entry_free_cb(0, (void **)&entry_ctx, 0, NULL);
}

void library_entry_dup_cb(const char *table_name, void **to, void **from, long argl, void* argp)
{
	struct library_entry_ctx *entry_ctx=(struct library_entry_ctx *)(*from);
	pthread_mutex_lock(&(entry_ctx->lock));
	entry_ctx->ref_cnt++;
	pthread_mutex_unlock(&(entry_ctx->lock));
	*to=entry_ctx;
}

int get_statistics_option_type_str2idx(const char *statistics_option_type)
{
	size_t i = 0;
	const char *statistics_option_name[] = {"none", "brief", "elaborate"};
	for (i = 0; i < sizeof(statistics_option_name) / sizeof(const char *); i++)
	{
		if (0 == strcasecmp(statistics_option_type, statistics_option_name[i]))
			break;
	}
	return i;
}

int get_category_type_str2idx(const char *category)
{
	size_t i = 0;
	const char *category_name[] = {"unknown", "geoip", "country_code", "asn", "website_category", "internet_service", "security_threat", "compliance_risk"};
	for (i = 0; i < sizeof(category_name) / sizeof(const char *); i++)
	{
		if (0 == strcasecmp(category, category_name[i]))
			break;
	}
	return i;
}

void library_tag_new_cb(const char *table_name, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	cJSON* library_tag_json = cJSON_Parse(table_line);
	if(library_tag_json == NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "LIBRARY_TAG parse table_line failed. table_line:%s", table_line);
		return;
	}

	struct library_tag_ctx *tag_ctx = ALLOC(struct library_tag_ctx, 1);
	cJSON *item = cJSON_GetObjectItem(library_tag_json, "uuid");
	if(item && item->type==cJSON_String)
	{
		tag_ctx->uuid=strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(library_tag_json, "statistics_option");
	if(item && item->type==cJSON_String)
	{
		tag_ctx->option_type=(enum statistics_option_type)get_statistics_option_type_str2idx(item->valuestring);
	}

	item = cJSON_GetObjectItem(library_tag_json, "category");
	if(item && item->type==cJSON_String)
	{
		tag_ctx->category=(enum category_type)get_category_type_str2idx(item->valuestring);
	}

	item = cJSON_GetObjectItem(library_tag_json, "tag_key");
	if(item && item->type==cJSON_String)
	{
		tag_ctx->tag_key=strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(library_tag_json, "tag_value");
	if(item && item->type==cJSON_String)
	{
		tag_ctx->tag_value=strdup(item->valuestring);
	}
	tag_ctx->ref_cnt=1;
	pthread_mutex_init(&(tag_ctx->lock), NULL);

	cJSON_Delete(library_tag_json);
	*ad=tag_ctx;
	return;
}

void library_tag_free_cb(const char *table_name, void **ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}

	struct library_tag_ctx *tag_ctx=(struct library_tag_ctx *)(*ad);
	pthread_mutex_lock(&(tag_ctx->lock));
	tag_ctx->ref_cnt--;
	if(tag_ctx->ref_cnt>0)
	{
		pthread_mutex_unlock(&(tag_ctx->lock));
		return;
	}
	pthread_mutex_unlock(&(tag_ctx->lock));
	pthread_mutex_destroy(&(tag_ctx->lock));

	if(tag_ctx->tag_key)
	{
		FREE(&tag_ctx->tag_key);
	}
	if(tag_ctx->tag_value)
	{
		FREE(&tag_ctx->tag_value);
	}
	if(tag_ctx->uuid)
	{
		FREE(&tag_ctx->uuid);
	}

	FREE(&tag_ctx);
	*ad=NULL;
	return;
}

void library_tag_dup_cb(const char *table_name, void **to, void **from, long argl, void* argp)
{
	struct library_tag_ctx *tag_ctx=(struct library_tag_ctx *)(*from);
	pthread_mutex_lock(&(tag_ctx->lock));
	tag_ctx->ref_cnt++;
	pthread_mutex_unlock(&(tag_ctx->lock));
	*to=tag_ctx;

	return;
}

void library_tag_free(struct library_tag_ctx *tag_ctx)
{
	library_tag_free_cb(0, (void **)&tag_ctx, 0, NULL);
}

void attribute_dict_new_cb(const char *table_name, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	cJSON* attribute_dict_json = cJSON_Parse(table_line);
	if(attribute_dict_json == NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "ATTRIBUTE_DICT parse table_line failed. table_line:%s", table_line);
		return;
	}

	struct attribute_dict_ctx *dict_ctx= ALLOC(struct attribute_dict_ctx, 1);
	cJSON *attribute_name = cJSON_GetObjectItem(attribute_dict_json, "attribute_name");
	if(attribute_name && attribute_name->type==cJSON_String)
	{
		dict_ctx->attribute_name=strdup(attribute_name->valuestring);
	}

	cJSON *object_table_name = cJSON_GetObjectItem(attribute_dict_json, "object_table_name");
	if(object_table_name && object_table_name->type==cJSON_String)
	{
		dict_ctx->object_table_name=strdup(object_table_name->valuestring);
	}

	cJSON *available_object_type = cJSON_GetObjectItem(attribute_dict_json, "available_object_type");
	if(available_object_type && available_object_type->type==cJSON_String)
	{
		dict_ctx->available_object_type=strdup(available_object_type->valuestring);
	}

	dict_ctx->ref_cnt=1;
	pthread_mutex_init(&(dict_ctx->lock), NULL);

	cJSON_Delete(attribute_dict_json);
	*ad=dict_ctx;
	return;
}

void attribute_dict_dup_cb(const char *table_name, void **to, void **from, long argl, void* argp)
{
	struct attribute_dict_ctx *dict_ctx=(struct attribute_dict_ctx *)(*from);
	pthread_mutex_lock(&(dict_ctx->lock));
	dict_ctx->ref_cnt++;
	pthread_mutex_unlock(&(dict_ctx->lock));
	*to=dict_ctx;

	return;
}

void attribute_dict_free_cb(const char *table_name, void **ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}

	struct attribute_dict_ctx *dict_ctx=(struct attribute_dict_ctx *)(*ad);
	pthread_mutex_lock(&(dict_ctx->lock));
	dict_ctx->ref_cnt--;
	if(dict_ctx->ref_cnt>0)
	{
		pthread_mutex_unlock(&(dict_ctx->lock));
		return;
	}
	pthread_mutex_unlock(&(dict_ctx->lock));
	pthread_mutex_destroy(&(dict_ctx->lock));

	if(dict_ctx->attribute_name)
	{
		FREE(&dict_ctx->attribute_name);
	}
	if(dict_ctx->attribute_name)
	{
		FREE(&dict_ctx->object_table_name);
	}
	if(dict_ctx->available_object_type)
	{
		FREE(&dict_ctx->available_object_type);
	}

	FREE(&dict_ctx);
	*ad=NULL;
	return;
}

void attribute_dict_free(struct attribute_dict_ctx *dict_ctx)
{
	attribute_dict_free_cb(0, (void **)&dict_ctx, 0, NULL);
}

unsigned char action_type_str2idx(const char *action_str)
{
	const char *action_name[__PG_ACTION_MAX]={0};
	action_name[PG_ACTION_NONE] = "none";
	action_name[PG_ACTION_MONIT] = "monitor";
	action_name[PG_ACTION_INTERCEPT] = "intercept";
	action_name[PG_ACTION_NO_INTERCEPT] = "no_intercept";
	action_name[PG_ACTION_ACTIVE_DEFENCE] = "active_defence";
	action_name[PG_ACTION_WANNAT] = "wannat";
	action_name[PG_ACTION_REJECT] = "deny";
	action_name[PG_ACTION_SHAPING] = "shaping";
	action_name[PG_ACTION_MANIPULATE] = "manipulate";
	action_name[PG_ACTION_SERVICE_CHAINING] = "service_chaining";
	action_name[PG_ACTION_WHITELIST] = "allow";
	action_name[PX_ACTION_SHUNT] = "shunt";
	action_name[PG_STATISTICS] = "statistics";

	int action = PG_ACTION_MANIPULATE;
	for ( action = PG_ACTION_NONE; action < __PG_ACTION_MAX; action++)
	{
		if (action_name[action] != NULL && 0 == strcasecmp(action_str, action_name[action]))
			break;
	}
	return action;
}

void compile_table_new_cb(const char *table_name, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	cJSON* policy_rule_json = cJSON_Parse(table_line);
	if(policy_rule_json == NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "%s parse table_line failed. table_line:%s", table_name, table_line);
		return;
	}

	struct rule_data_ctx *rule_ctx=ALLOC(struct rule_data_ctx, 1);

	cJSON *item = cJSON_GetObjectItem(policy_rule_json, "uuid");
	if(item && item->type==cJSON_String)
	{
		uuid_parse(item->valuestring, rule_ctx->rule_uuid);
	}
	item = cJSON_GetObjectItem(policy_rule_json, "action");
	if(item && item->type==cJSON_String)
	{
		rule_ctx->action=action_type_str2idx(item->valuestring);
	}
	item = cJSON_GetObjectItem(policy_rule_json, "service");
	if(item && item->type==cJSON_Number)
	{
		rule_ctx->service_id=item->valueint;
	}

	cJSON_Delete(policy_rule_json);

	rule_ctx->ref_cnt=1;
	pthread_mutex_init(&(rule_ctx->lock), NULL);

	*ad = rule_ctx;
}

void compile_free_data(const char *table_name, void **ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}
	struct rule_data_ctx *rule_ctx=(struct rule_data_ctx *)(*ad);
	pthread_mutex_lock(&(rule_ctx->lock));
	rule_ctx->ref_cnt--;
	if(rule_ctx->ref_cnt>0)
	{
		pthread_mutex_unlock(&(rule_ctx->lock));
		return;
	}
	pthread_mutex_unlock(&(rule_ctx->lock));
	pthread_mutex_destroy(&(rule_ctx->lock));
	FREE(&rule_ctx);
	*ad=NULL;
	return;
}

void compile_free(struct rule_data_ctx *compile_ctx)
{
	compile_free_data(0, (void **)&compile_ctx, 0, NULL);
}

void compile_dup_data(const char *table_name, void **to, void **from, long argl, void *argp)
{
	struct rule_data_ctx *rule_ctx=(struct rule_data_ctx *)(*from);
	pthread_mutex_lock(&(rule_ctx->lock));
	rule_ctx->ref_cnt++;
	pthread_mutex_unlock(&(rule_ctx->lock));
	*to=rule_ctx;

	return;
}

static inline int multiple_hit_actions(enum policy_action __action)
{
	if (__action == PG_ACTION_MONIT || __action == PG_ACTION_SHAPING || __action == PG_ACTION_SERVICE_CHAINING || __action == PG_STATISTICS)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static enum policy_action decide_policy_action(int vsys_id, int compile_table_id, uuid_t *results, size_t n_hit,
											struct rule_data_ctx ** enforce_rules, size_t * n_enforce, struct rule_data_ctx **hit_rules)
{
	size_t n_monit = 0, exist_enforce_num = 0, i = 0;
	enum policy_action prior_action = PG_ACTION_NONE;
	struct rule_data_ctx *rule_ctx=NULL;
	struct rule_data_ctx *hit_rules_ex=NULL;

	if(n_hit < 0)
	{
		return prior_action;
	}

	char result_uuid_str[UUID_STR_LEN]={0};
	hit_rules_ex=ALLOC(struct rule_data_ctx, n_hit);
	for (i = 0; i < n_hit && i<MAX_SCAN_RESULT; i++)
	{
		uuid_unparse(results[i], result_uuid_str);
		rule_ctx =(struct rule_data_ctx *)maat_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], get_plugin_table_name((enum policy_rule_type)compile_table_id), (const char *)result_uuid_str, strlen(result_uuid_str));
		if(!rule_ctx)
		{
			continue;
		}
		memcpy(hit_rules_ex+i, rule_ctx, sizeof(struct rule_data_ctx));
		compile_free(rule_ctx);
	}
	*hit_rules=hit_rules_ex;

	const struct rule_data_ctx * prior_rule = hit_rules_ex;
	struct rule_data_ctx monit_rule[n_hit];

	for (i = 0; i < n_hit && i<MAX_SCAN_RESULT; i++)
	{
		unsigned char __expand_action = (unsigned char) hit_rules_ex[i].action;
		enum policy_action __action = (enum policy_action) __expand_action;
		if (multiple_hit_actions(__action))
		{
			memcpy(monit_rule + n_monit, hit_rules_ex + i, sizeof(struct rule_data_ctx));
			n_monit++;
		}
		if (action_cmp(__action, prior_action) > 0)
		{
			prior_rule = hit_rules_ex + i;
			prior_action = __action;
		}
		else if (action_cmp(__action, prior_action) == 0)
		{
			if(uuid_compare(hit_rules_ex[i].rule_uuid, prior_rule->rule_uuid) > 0)
			{
				prior_rule = hit_rules_ex + i;
			}
		}
		else
		{
			continue;
		}
	}

	if(compile_table_id == TSG_TABLE_SECURITY && prior_action == PX_ACTION_SHUNT)
	{
		if(*n_enforce==0)
		{
			*enforce_rules=ALLOC(struct rule_data_ctx, 1);
		}
		*enforce_rules[0]=*prior_rule;
		*n_enforce=1;
		return PX_ACTION_SHUNT;
	}
	if(compile_table_id != TSG_TABLE_SECURITY && prior_action == PG_ACTION_WHITELIST)
	{
		if(*n_enforce==0)
		{
			*enforce_rules=ALLOC(struct rule_data_ctx, 1);
		}
		*enforce_rules[0]=*prior_rule;
		*n_enforce=1;
		return PG_ACTION_WHITELIST;
	}

	exist_enforce_num = *n_enforce;
	if (multiple_hit_actions(prior_action))
	{
		*n_enforce += n_monit;
	}
	else
	{
		*n_enforce += n_monit + 1;
	}

	*enforce_rules = (struct rule_data_ctx  *) realloc(*enforce_rules, sizeof(struct rule_data_ctx ) * (*n_enforce));
	if (multiple_hit_actions(prior_action))
	{
		memcpy(*enforce_rules + exist_enforce_num, monit_rule, n_monit * sizeof(struct rule_data_ctx ));
	}
	else
	{
		memmove(*enforce_rules+1, *enforce_rules, exist_enforce_num*sizeof(struct rule_data_ctx ));
		memcpy(*enforce_rules, prior_rule, sizeof(struct rule_data_ctx ));
		memcpy(*enforce_rules + exist_enforce_num + 1, monit_rule, n_monit * sizeof(struct rule_data_ctx ));
	}
	return prior_action;
}

static inline int request_in_fqdn_cat(int table_id)
{
	if( table_id==TSG_OBJ_SSL_CN || table_id==TSG_OBJ_SSL_SAN
	   || table_id==TSG_OBJ_DNS_QNAME || table_id==TSG_OBJ_DOH_QNAME || table_id==TSG_OBJ_DST_SERVER_FQDN)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void add_tag_ids_to_hit_paths(cJSON *hitPaths, int table_id, struct library_scan_path *ip_ctx)
{
	cJSON *histObj=NULL;
	struct library_hit_path *ip_entry=NULL;

	while ((ip_entry=(struct library_hit_path *)utarray_next(ip_ctx->ut_array_by_context, ip_entry)) != NULL)
	{
		if(ip_entry->table_id == table_id)
		{
			for(int i=0; i < ip_entry->entry_num; i++)
			{
				histObj=cJSON_CreateObject();
				cJSON_AddItemToArray(hitPaths, histObj);
				cJSON_AddStringToObject(histObj, "entry_uuid", ip_entry->tag[i].uuid);
				cJSON_AddStringToObject(histObj, "tag_uuid", ip_entry->tag[i].tag_uuid);
			}
		}
	}

	return;
}

/*In the case of multiple hits, the hit path is append behavior to obtain the last hit path force***/
int http_hit_policy_match(uuid_t result_config[], int cnt, uuid_t config)
{
	int i = 0;

	for(i=0; i<cnt; i++)
	{
		if(uuid_compare(result_config[i], config) == 0)
		{
			return 1;
		}
	}
	return 0;
}

int hit_rule_match_is_duplicate(struct maat_hit_path *src, struct maat_hit_path dest, int result_cnt)
{
	for(int i = 0; i < result_cnt; i++)
	{
		if(src[i].top_object_uuid == dest.top_object_uuid)
		{
			return 1;
		}
	}
	return 0;
}

cJSON *get_tunnel_endpoint_attribute(cJSON *attributes)
{
	cJSON *item=NULL, *subchild=NULL;

	for (item = attributes->child; item != NULL; item = item->next)
	{
		subchild = cJSON_GetObjectItem(item, "attribute_name");
		if(subchild && subchild->type==cJSON_String && strncasecmp(subchild->valuestring, "tunnel_endpoint_object", 22) == 0)
		{
			return item;
		}
	}
	return NULL;
}

int hit_object_exists_by_ids(cJSON* hitPaths, uuid_t item_id, uuid_t superior_object_id)
{
	cJSON *hitsObj=NULL;
	uuid_t item_valuestring_uuid, superiorId_valuestring_uuid;

	/*In cases of multiple hits, although the compile_id is inconsistent, the item_id and superior_object_id remain consistent.**/
	/*For tunnel_endpointa if hit non and tunnel_endpointb hit not logic the same nth_scan record will exist **/
	for(hitsObj = hitPaths->child; hitsObj != NULL; hitsObj = hitsObj->next)
	{
		cJSON *itemId = cJSON_GetObjectItem(hitsObj, "item_uuid");
		cJSON *superiorId = cJSON_GetObjectItem(hitsObj, "superior_object_uuid");

		if(itemId==NULL || superiorId==NULL)
		{
			continue;
		}
		uuid_clear(item_valuestring_uuid);
		uuid_parse(itemId->valuestring, item_valuestring_uuid);
		uuid_clear(superiorId_valuestring_uuid);
		uuid_parse(superiorId->valuestring, superiorId_valuestring_uuid);
		if((uuid_compare(item_valuestring_uuid, item_id) == 0) && (uuid_compare(superiorId_valuestring_uuid, superior_object_id)==0))
		{
			return 1;
		}
	}
	return 0;
}

void http_get_scan_status(struct request_object_list *request_object, int compile_table_id, cJSON *attributes, struct policy_scan_ctx * ctx)
{
	int i=0, j=0;
	cJSON *attributeObj=NULL;

	attributeObj=request_object->attributes;
	if(request_object->table_id == TSG_OBJ_TUNNEL)
	{
		cJSON_Delete(attributeObj);
		attributeObj=NULL;

		attributeObj = get_tunnel_endpoint_attribute(attributes);
		if(attributeObj == NULL)
		{
			attributeObj = cJSON_CreateObject();
			cJSON_AddStringToObject(attributeObj, "attribute_value_type", "ip");
			cJSON_AddStringToObject(attributeObj, "attribute_name", "tunnel_endpoint_object");
		}
	}

	cJSON* hitPaths = cJSON_GetObjectItem(attributeObj, "hit_paths");
	if(hitPaths != NULL && hitPaths->type != cJSON_Array)
	{
		cJSON_DeleteItemFromObject(attributeObj, "hit_paths");
		hitPaths=NULL;
	}
	if (hitPaths == NULL)
	{
		cJSON_AddItemToArray(attributes, attributeObj);
		hitPaths = cJSON_CreateArray();
		cJSON_AddItemToObject(attributeObj, "hit_paths", hitPaths);
	}
	add_tag_ids_to_hit_paths(hitPaths, request_object->table_id, &ctx->scan_path);

	cJSON *histObj=NULL;
	for(i=0; i< ctx->n_read; i++)
	{
		for(j=0; j<=request_object->merge_nth_scan_num; j++)
		{
			if (request_object->merge_nth_scan[j] == ctx->hit_path[i].Nth_scan)
			{
				if(uuid_is_null(ctx->hit_path[i].top_object_uuid) == 1)
				{
					uuid_copy(ctx->hit_path[i].top_object_uuid, ctx->hit_path[i].sub_object_uuid);
				}

				if(hit_object_exists_by_ids(hitPaths, ctx->hit_path[i].item_uuid, ctx->hit_path[i].top_object_uuid))
				{
					break;
				}

				if(ctx->hit_path[i].item_uuid < 0)
				{
					continue;
				}

				histObj=cJSON_CreateObject();
				cJSON_AddItemToArray(hitPaths, histObj);
				cJSON_AddUuidToObject(histObj, "item_uuid", ctx->hit_path[i].item_uuid);
				cJSON_AddUuidToObject(histObj, "superior_object_uuid", ctx->hit_path[i].top_object_uuid);
				break;
			}
		}
	}
}

int policy_verify_regex_expression(const char *expression)
{
	return maat_helper_verify_regex_expression(expression);
}

int get_ip_addr_table_name(struct library_scan_path *ip_ctx, int Nth_scan, int top_group_id, cJSON *topObject)
{
	const char * table_name[__TSG_OBJ_MAX] = {0};
	table_name[TSG_OBJ_SOURCE_ADDR] = "ATTR_SOURCE_IP";
	table_name[TSG_OBJ_DESTINATION_ADDR] = "ATTR_DESTINATION_IP";
	table_name[TSG_OBJ_INTERNAL_ADDR]="ATTR_INTERNAL_IP";
	table_name[TSG_OBJ_EXTERNAL_ADDR]="ATTR_EXTERNAL_IP";

	struct library_hit_path *ip_entry=NULL;
	while ((ip_entry=(struct library_hit_path *)utarray_next(ip_ctx->ut_array_by_context, ip_entry)) != NULL)
	{
		for(int i = 0; i < ip_entry->Nth_scan_num; i++)
		{
			if(ip_entry->Nth_scan[i] == Nth_scan)
			{
				cJSON_AddNumberToObject(topObject, "tag_id", top_group_id);
				cJSON_AddStringToObject(topObject, "table_name", table_name[ip_entry->table_id]);
				return 1;
			}
		}
	}
	return 0;
}

const char *get_library_virtual_table_name(int table_id)
{
	const char * table_name[__TSG_OBJ_MAX] = {0};
	table_name[TSG_OBJ_SOURCE_ADDR] = "ATTR_SOURCE_IP";
	table_name[TSG_OBJ_DESTINATION_ADDR] = "ATTR_DESTINATION_IP";
	table_name[TSG_OBJ_INTERNAL_ADDR]="ATTR_INTERNAL_IP";
	table_name[TSG_OBJ_EXTERNAL_ADDR]="ATTR_EXTERNAL_IP";
	table_name[TSG_OBJ_SSL_CN]="ATTR_SERVER_FQDN";
	table_name[TSG_OBJ_SSL_SAN]="ATTR_SERVER_FQDN";
	table_name[TSG_OBJ_DNS_QNAME]="ATTR_SERVER_FQDN";
	table_name[TSG_OBJ_DOH_QNAME]="ATTR_SERVER_FQDN";
	table_name[TSG_OBJ_DST_SERVER_FQDN]="ATTR_SERVER_FQDN";
	return table_name[table_id];
}

int add_tags_table_name(struct library_scan_path *ip_ctx, int Nth_scan, uuid_t top_object_uuid, cJSON *topObject)
{
	struct library_hit_path *ip_entry=NULL;

	while ((ip_entry=(struct library_hit_path *)utarray_next(ip_ctx->ut_array_by_context, ip_entry)) != NULL)
	{
		for(int i = 0; i < ip_entry->Nth_scan_num; i++)
		{
			if(ip_entry->Nth_scan[i] == Nth_scan)
			{
				char tag_uuid_str[UUID_STR_LEN]={0};
				uuid_unparse(top_object_uuid, tag_uuid_str);
				cJSON_AddStringToObject(topObject, "tag_uuid", tag_uuid_str);
				cJSON_AddStringToObject(topObject, "attribute_name", get_library_virtual_table_name(ip_entry->table_id));
				goto finish;
			}
		}
	}
finish:
	return 0;
}

int add_object_table_name(UT_array *ut_array_by_object, int Nth_scan, uuid_t top_object_uuid, cJSON *topObject)
{
	char object_uuid_str[UUID_STR_LEN]={0};
	cJSON *attributeObj=NULL, *subchild=NULL;
	struct request_object_list *request_object=NULL;

	/*The priority of the tag is higher than that of the object_id.**/
	cJSON *tag_id = cJSON_GetObjectItem(topObject, "tag_uuid");
	if(tag_id != NULL)
	{
		goto finish;
	}

	uuid_unparse(top_object_uuid, object_uuid_str);
	cJSON_AddStringToObject(topObject, "object_uuid", object_uuid_str);
	while ((request_object=(struct request_object_list *)utarray_next(ut_array_by_object, request_object)) != NULL)
	{
		for(int j=0; j<= request_object->merge_nth_scan_num; j++)
		{
			if (request_object->merge_nth_scan[j] == Nth_scan)
			{
				attributeObj=request_object->attributes;
				subchild = cJSON_GetObjectItem(attributeObj, "attribute_name");
				if(subchild && subchild->type==cJSON_String)
				{
					cJSON_AddStringToObject(topObject, "attribute_name", subchild->valuestring);
				}
				goto finish;
			}
		}
	}
finish:
	return 0;
}

int http_hit_policy_list(struct verify_policy_query *verify_policy, size_t hit_cnt, cJSON *data_obj, struct policy_scan_ctx *ctx)
{
	bool succeeded = false;
	size_t rules=0, i=0,j=0;
	uuid_t result_rule_uuid[MAX_SCAN_RESULT]={0};

	int vsys_id = verify_policy->vsys_id;
	int compile_table_id = verify_policy->compile_table_id;

	if (hit_cnt <= 0)
	{
		return 0;
	}

	ctx->hit_cnt = hit_cnt > MAX_SCAN_RESULT ? MAX_SCAN_RESULT : hit_cnt;
	ctx->action = decide_policy_action(vsys_id, compile_table_id, ctx->result, hit_cnt, &ctx->enforce_rules, &ctx->n_enforce, &ctx->hit_rules);
	ctx->hit_cnt = hit_cnt;
	cJSON *hit_obj=NULL, *policy_obj=NULL;
	cJSON *topObjectList=NULL, *topObject=NULL;
	hit_obj=cJSON_CreateArray();
	cJSON_AddItemToObject(data_obj, "hit_rules", hit_obj);
	if (ctx->hit_cnt >= 1)
	{
		for (i = 0; i < ctx->hit_cnt; i++)
		{
			if(http_hit_policy_match(result_rule_uuid, i, ctx->hit_rules[i].rule_uuid))
			{
				continue;
			}
			succeeded = false;
			policy_obj=cJSON_CreateObject();

			char rule_uuid_str[UUID_STR_LEN]={0};
			uuid_unparse(ctx->hit_rules[i].rule_uuid, rule_uuid_str);
			cJSON_AddStringToObject(policy_obj, "uuid", rule_uuid_str);
			cJSON_AddStringToObject(policy_obj, "policyName", "");

			for (rules = 0; rules < ctx->n_enforce; rules++)
			{
				if(uuid_compare(ctx->enforce_rules[rules].rule_uuid, ctx->hit_rules[i].rule_uuid) == 0)
				{
					cJSON_AddBoolToObject(policy_obj, "is_execute", true);
					succeeded = true;
				}
			}
			if (succeeded == false)
			{
				cJSON_AddBoolToObject(policy_obj, "is_execute", false);
			}
			cJSON_AddItemToArray(hit_obj, policy_obj);
			uuid_copy(result_rule_uuid[i], ctx->hit_rules[i].rule_uuid);
			struct maat_hit_path result_hit_path[MAX_SCAN_RESULT]={0}; int result_cnt=0;

			topObjectList=cJSON_CreateArray();
			cJSON_AddItemToObject(policy_obj, "top_object_list", topObjectList);
			for(j=0; j<=(size_t)ctx->n_read; j++)
			{
				if(uuid_is_null(ctx->hit_path[j].rule_uuid) != 1 && uuid_compare(ctx->hit_path[j].rule_uuid,ctx->hit_rules[i].rule_uuid)==0)
				{
					if(hit_rule_match_is_duplicate(result_hit_path, ctx->hit_path[j], result_cnt))
					{
						continue;
					}
					else
					{
						memcpy(&result_hit_path[result_cnt], &ctx->hit_path[j], sizeof(struct maat_hit_path));
						result_cnt++;
					}
					topObject=cJSON_CreateObject();
					add_tags_table_name(&ctx->scan_path, ctx->hit_path[j].Nth_scan, ctx->hit_path[j].top_object_uuid, topObject);
					add_object_table_name(verify_policy->ut_array_by_object, ctx->hit_path[j].Nth_scan, ctx->hit_path[j].top_object_uuid, topObject);
					cJSON_AddNumberToObject(topObject, "negate_option", ctx->hit_path[j].negate_option);
					cJSON_AddNumberToObject(topObject, "condition_index", ctx->hit_path[j].condition_index);
					cJSON_AddItemToArray(topObjectList, topObject);
				}
			}
		}
	}
	return 0;
}

int ip_addr_to_address(struct ipaddr *ip_addr, struct ip_addr *dest_ip, struct ip_addr *source_ip)
{
	if(ip_addr==NULL) return -1;
	if (ip_addr->addrtype == ADDR_TYPE_IPV4)
	{
		struct stream_tuple4_v4 *v4_addr = (struct stream_tuple4_v4 *)ip_addr->v4;
		source_ip->ip_type=4;
		source_ip->ipv4=v4_addr->saddr;
		dest_ip->ip_type=4;
		dest_ip->ipv4=v4_addr->daddr;
	}
	if (ip_addr->addrtype == ADDR_TYPE_IPV6)
	{
		struct stream_tuple4_v6 *v6_addr = (struct stream_tuple4_v6 *)ip_addr->v6;
		source_ip->ip_type=6;
		memcpy((char *)(source_ip->ipv6), v6_addr->saddr, IPV6_ADDR_LEN);
		dest_ip->ip_type=6;
		memcpy((char *)(dest_ip->ipv6),v6_addr->daddr, IPV6_ADDR_LEN);
	}
	return 0;
}

static int scan_object(struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt, char *object_uuid_str, const char *table_name, const char *attribute_name)
{
	size_t n_hit_result=0;
	uuid_t objects_uuid;
	int scan_ret=0, hit_cnt_group=0;

	struct maat_hit_object objects;
	memset(&objects, 0, sizeof(objects));
	uuid_parse(object_uuid_str, objects_uuid);
	uuid_copy(objects.object_uuid, objects_uuid);

	scan_ret = maat_scan_object(g_policy_rt->feather[vsys_id], table_name, attribute_name, &objects, 1,
							   ctx->result+hit_cnt+hit_cnt_group, MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_group+=n_hit_result;
	}

	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], table_name, attribute_name, ctx->result+hit_cnt+hit_cnt_group,
								   MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_group+=n_hit_result;
	}
	return hit_cnt_group;
}

#if 0
int is_tag_id_in_array(long long *tag_id_array, int n_tag_ids, long long tag_id)
{
	for(int i=0; i < n_tag_ids; i++)
	{
		if(tag_id_array[i] == tag_id)
		{
			return 1;
		}
	}
	return 0;
}

int get_fqdn_entry_tag_ids(cJSON *hit_library, int vsys_id, const char *fqdn)
{
	int ret=0, hit_fqdn_entry=0;
	cJSON *fqdn_entry_item=NULL;
	int n_tag_ids=0;
	long long tag_id_array[MAX_TAG_ID_NUM]={0};

	if(fqdn == NULL)
	{
		return 0;
	}

	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] fqdn=%s", fqdn);

	struct library_entry_ctx *entry_ctx[MAX_EX_DATA_LEN]={0};
	ret=maat_fqdn_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_FQDN_ENTRY], fqdn, (void **)entry_ctx, MAX_EX_DATA_LEN);
	for(int i=0; i < ret && i < MAX_EX_DATA_LEN; i++)
	{
		for(int j=0; j < entry_ctx[i]->n_tag_ids; j++)
		{
			if(is_tag_id_in_array(tag_id_array, n_tag_ids, entry_ctx[i]->tag_id_array[j]))
			{
				continue;
			}
			tag_id_array[n_tag_ids++] =  entry_ctx[i]->tag_id_array[j];
		}
		library_entry_free(entry_ctx[i]);
	}

	char *tag_ids; int length = 0;
	if(n_tag_ids > 0)
	{
		fqdn_entry_item=cJSON_CreateObject();
		for (int i = 0; i < n_tag_ids; i++)
		{
			if (i == 0)
			{
				length = asprintf(&tag_ids, "%lld", tag_id_array[i]);
			}
			else
			{
				length = asprintf(&tag_ids, "%s,%lld", tag_ids, tag_id_array[i]);
			}
   		 }
		 cJSON_AddStringToObject(fqdn_entry_item, "tag_ids", tag_ids);
		 cJSON_AddItemToArray(hit_library, fqdn_entry_item);
	}

	return hit_fqdn_entry;
}
#endif

int get_fqdn_entry_tag_ids(cJSON *hit_library, int vsys_id, const char *fqdn)
{
	int ret=0, hit_fqdn_entry=0;
	cJSON *fqdn_entry_item=NULL;

	if(fqdn == NULL)
	{
		return 0;
	}

	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] fqdn=%s", fqdn);

	struct library_entry_ctx *entry_ctx[MAX_EX_DATA_LEN]={0};
	ret=maat_fqdn_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "FQDN_ENTRY", fqdn, (void **)entry_ctx, MAX_EX_DATA_LEN);
	for(int i=0; i < ret && i < MAX_EX_DATA_LEN; i++)
	{
		fqdn_entry_item=cJSON_CreateObject();
		cJSON_AddStringToObject(fqdn_entry_item, "tag_uuids", entry_ctx[i]->tag_uuids);
		cJSON_AddItemToArray(hit_library, fqdn_entry_item);
		hit_fqdn_entry++;

		library_entry_free(entry_ctx[i]);
	}

	return hit_fqdn_entry;
}

int get_ip_entry_tag_ids(cJSON *hit_library, int vsys_id, struct ipaddr *ip_addr)
{
	int ret=0, hit_ip_entry=0;
	cJSON *ip_entry_item=NULL;

	if(ip_addr == NULL)
	{
		return 0;
	}

	struct ip_addr dest_ip, source_ip;
	ip_addr_to_address(ip_addr, &dest_ip, &source_ip);

	struct library_entry_ctx *entry_ctx[MAX_EX_DATA_LEN]={0};
	ret = maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "IP_ADDR_ENTRY", &source_ip, (void **)&entry_ctx, MAX_EX_DATA_LEN);
	for(int i=0; i < ret && i < MAX_EX_DATA_LEN; i++)
	{
		ip_entry_item=cJSON_CreateObject();
		cJSON_AddStringToObject(ip_entry_item, "tag_uuids", entry_ctx[i]->tag_uuids);
		cJSON_AddItemToArray(hit_library, ip_entry_item);
		hit_ip_entry++;

		library_entry_free(entry_ctx[i]);
	}
	return hit_ip_entry;
}

enum category_type get_library_tag_category(char *tag_uuid, int vsys_id)
{
	struct library_tag_ctx *tag_ctx =(struct library_tag_ctx *)maat_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "LIBRARY_TAG", (const char *)tag_uuid, strlen(tag_uuid));
	if(tag_ctx != NULL)
	{
		enum category_type category = tag_ctx->category;
		library_tag_free(tag_ctx);
		return category;
	}

	return CATEGORY_TYPE_UNKNOWN;
}

int ip_entry_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int scan_ret=0, hit_cnt_ip=0;
	struct maat_hit_path hit_path[HIT_PATH_SIZE];
	struct library_entry_ctx *source_ip_entry[MAX_EX_DATA_LEN]={0};
	struct library_entry_ctx *destination_ip_entry[MAX_EX_DATA_LEN]={0};

	struct ip_addr dip, sip;
	ip_addr_to_address(request->ip_addr, &dip, &sip);

	memset(hit_path, 0, sizeof(struct maat_hit_path)*HIT_PATH_SIZE);

	int ret1=0, ret2=0;
	if(request->table_id == TSG_OBJ_SOURCE_ADDR || request->table_id == TSG_OBJ_INTERNAL_ADDR)
	{
		ret1 = maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "IP_ADDR_ENTRY", &sip, (void **)&source_ip_entry, MAX_EX_DATA_LEN);
	}
	if(request->table_id == TSG_OBJ_DESTINATION_ADDR || request->table_id == TSG_OBJ_EXTERNAL_ADDR)
	{
		ret2 = maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "IP_ADDR_ENTRY", &dip, (void **)&destination_ip_entry, MAX_EX_DATA_LEN);
	}

	struct library_hit_path ip_entry;
	memset(&ip_entry, 0, sizeof(ip_entry));

	if(ret1 > 0)
	{
		for(int i=0; i < ret1 && i < MAX_EX_DATA_LEN; i++)
		{
			if(source_ip_entry[i] == NULL)
			{
				continue;
			}

			for(int tag_id=0; tag_id<source_ip_entry[i]->n_tag_uuids; tag_id++)
			{
				scan_ret = scan_object(ctx, vsys_id, hit_cnt, source_ip_entry[i]->tag_uuid_array[tag_id], "TSG_OBJ_IP_ADDR", request->attribute_name);
				if(scan_ret > 0)
				{
					hit_cnt_ip+=scan_ret;
				}

				ip_entry.table_id = request->table_id;
				ip_entry.tag[ip_entry.entry_num].uuid = strdup(source_ip_entry[i]->uuid);
				ip_entry.tag[ip_entry.entry_num].tag_uuid = strdup(source_ip_entry[i]->tag_uuid_array[tag_id]);
				ip_entry.tag[ip_entry.entry_num].category = get_library_tag_category(source_ip_entry[i]->tag_uuid_array[tag_id], vsys_id);
				ip_entry.entry_num++;

				ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);
				ip_entry.Nth_scan[ip_entry.Nth_scan_num++] = maat_state_get_scan_count(ctx->scan_mid);
			}
			library_entry_free(source_ip_entry[i]);
		}
		if(ip_entry.entry_num > 0)
		{
			utarray_push_back(ctx->scan_path.ut_array_by_context, &ip_entry);
		}
	}

	if(ret2 > 0)
	{
		for(int i=0; i < ret2 && i < MAX_EX_DATA_LEN; i++)
		{
			if(destination_ip_entry[i] == NULL)
			{
				continue;
			}

			for(int tag_id=0; tag_id<destination_ip_entry[i]->n_tag_uuids; tag_id++)
			{
				scan_ret = scan_object(ctx, vsys_id, hit_cnt, destination_ip_entry[i]->tag_uuid_array[tag_id],  "TSG_OBJ_IP_ADDR", request->attribute_name);
				if(scan_ret > 0)
				{
					hit_cnt_ip+=scan_ret;
				}

				ip_entry.table_id = request->table_id;
				ip_entry.tag[ip_entry.entry_num].uuid = strdup(destination_ip_entry[i]->uuid);
				ip_entry.tag[ip_entry.entry_num].tag_uuid=strdup(destination_ip_entry[i]->tag_uuid_array[tag_id]);
				ip_entry.tag[ip_entry.entry_num].category = get_library_tag_category(destination_ip_entry[i]->tag_uuid_array[tag_id], vsys_id);
				ip_entry.entry_num++;

				ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);
				ip_entry.Nth_scan[ip_entry.Nth_scan_num++] = maat_state_get_scan_count(ctx->scan_mid);
			}
			library_entry_free(destination_ip_entry[i]);
		}
		if(ip_entry.entry_num > 0)
		{
			utarray_push_back(ctx->scan_path.ut_array_by_context, &ip_entry);
		}
	}

	return hit_cnt_ip;
}

int get_fqdn_category_id(struct request_object_list *request, struct policy_scan_ctx * ctx, int vsys_id, const char *fqdn, int table_id, int hit_cnt)
{
	size_t n_read=0;
	int ret=0, hit_cnt_fqdn=0;
	struct library_entry_ctx *fqdn_entry_ctx[MAX_EX_DATA_LEN]={0};

	struct library_hit_path fqdn_entry;
	memset(&fqdn_entry, 0, sizeof(fqdn_entry));

	ret=maat_fqdn_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "FQDN_ENTRY", fqdn, (void **)fqdn_entry_ctx, MAX_EX_DATA_LEN);
	for(int i=0; i < ret && i < MAX_EX_DATA_LEN; i++)
	{
		if(fqdn_entry_ctx[i] == NULL)
		{
			continue;
		}

		for(int tag_id=0; tag_id<fqdn_entry_ctx[i]->n_tag_uuids; tag_id++)
		{
			fqdn_entry.table_id = request->table_id;
			fqdn_entry.tag[fqdn_entry.entry_num].uuid=strdup(fqdn_entry_ctx[i]->uuid);
			fqdn_entry.tag[fqdn_entry.entry_num].tag_uuid=strdup(fqdn_entry_ctx[i]->tag_uuid_array[tag_id]);
			fqdn_entry.entry_num++;

		}
		library_entry_free(fqdn_entry_ctx[i]);
	}

	for(int i=0; i<fqdn_entry.entry_num; i++)
	{
		char *uuid = fqdn_entry.tag[i].tag_uuid;
		ret=scan_object(ctx, vsys_id, hit_cnt, uuid, "TSG_OBJ_FQDN", request->attribute_name);
		if(ret > 0)
		{
			hit_cnt_fqdn+=ret;
		}
		n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
		if(ret >= MAAT_SCAN_OK)
		{
			fqdn_entry.Nth_scan[fqdn_entry.Nth_scan_num++]=maat_state_get_scan_count(ctx->scan_mid);
			ctx->n_read=n_read;
		}
	}

	if(fqdn_entry.entry_num > 0)
	{
		utarray_push_back(ctx->scan_path.ut_array_by_context, &fqdn_entry);
	}
	return hit_cnt_fqdn;
}

int tunnel_level_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read, hit_path_cnt=0;
	int scan_ret=0, hit_cnt_tunnel=0;
	const char *object_uuid_level_array[]={"00000000-0000-0000-0000-000000000050", "00000000-0000-0000-0000-000000000051", "00000000-0000-0000-0000-000000000052",
										   "00000000-0000-0000-0000-000000000053", "00000000-0000-0000-0000-000000000054", "00000000-0000-0000-0000-000000000055",
										   "00000000-0000-0000-0000-000000000056", "00000000-0000-0000-0000-000000000057"};

	const char *object_uuid=object_uuid_level_array[request->numeric];
	scan_ret = scan_object(ctx, vsys_id, hit_cnt, (char *)object_uuid, "TSG_OBJ_TUNNEL_LEVEL", request->attribute_name);
	if(scan_ret > 0)
	{
		hit_cnt_tunnel += scan_ret;
	}
	if(scan_ret >= MAAT_SCAN_OK)
	{
		n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
		request->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);
		ctx->n_read=n_read;
		hit_path_cnt++;
	}
	request->merge_nth_scan_num = hit_path_cnt;
	return hit_cnt_tunnel;
}

const char* get_tunnel_type_table_id(char *tunnel_type)
{
	const char *attribute_name="ATTR_TUNNEL_GTP_ENDPOINT";
	const char *tunnel_type_map[] = {"GTP", "GRE", "IPv4/IPv6"};

	if(tunnel_type == NULL)
	{
		return attribute_name;
	}

	for (size_t i = 0; i < sizeof(tunnel_type_map) / sizeof(const char *); i++)
	{
		if (0 == strcasecmp(tunnel_type, tunnel_type_map[i]))
		{
			if(i == 0)
			{
				attribute_name = "ATTR_TUNNEL_GTP_ENDPOINT";
			}
			if(i == 1)
			{
				attribute_name = "ATTR_TUNNEL_GRE_ENDPOINT";
			}
			if(i == 2)
			{
				attribute_name = "ATTR_TUNNEL_IP_IN_IP_ENDPOINT";
			}
			break;
		}
	}
	return attribute_name;
}

int tunnel_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt, struct ipaddr *ip_addr)
{
	int logic =1;
	int i=0,hit_path_cnt=0;
	int n_read=0, hit_cnt_endpoint=0;
	int scan_ret=0, hit_cnt_tunnel=0;
	size_t n_hit_result=0;
	struct maat_hit_object objects;
	uuid_t result[MAX_SCAN_RESULT]={0};

	int hit_cnt_group=0;

	if(ctx->tunnel_scan_mid == NULL)
	{
		ctx->tunnel_scan_mid = maat_state_new(g_policy_rt->feather[vsys_id], ctx->thread_id);
		maat_state_set_scan_rule_table(ctx->tunnel_scan_mid, "TUNNEL_RULE_CONJUNCTION");
	}

	const char *attribute_name = get_tunnel_type_table_id(request->tunnel_type);
	if (ip_addr->addrtype == ADDR_TYPE_IPV4)
	{
		scan_ret = maat_scan_ipv4_port(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", attribute_name, ip_addr->v4->saddr, ip_addr->v4->source,
			 					  	   result, MAX_SCAN_RESULT, &n_hit_result, ctx->tunnel_scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_endpoint+=n_hit_result;
		}
	}

	if (ip_addr->addrtype == ADDR_TYPE_IPV6)
	{
		scan_ret = maat_scan_ipv6_port(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", attribute_name, ip_addr->v6->saddr, ip_addr->v6->source,
									   result, MAX_SCAN_RESULT, &n_hit_result, ctx->tunnel_scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_endpoint+=n_hit_result;
		}
	}

	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", attribute_name, result, MAX_SCAN_RESULT,
									&n_hit_result, ctx->tunnel_scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_endpoint+=n_hit_result;
	}

	if(hit_cnt_endpoint < 0)
	{
		goto finish;
	}

	if(ctx->tunnel_attr_count == 2)
	{
		logic=0;
	}

	for(i = 0; i< hit_cnt_endpoint; i++)
	{
		if(uuid_is_null(result[i]) != 1)
		{
			memset(&objects, 0, sizeof(objects));
			uuid_copy(objects.object_uuid, result[i]);
			scan_ret = maat_scan_object(g_policy_rt->feather[vsys_id], "TUNNEL_RULE", "ATTR_TUNNEL", &objects, 1,
							   ctx->result+hit_cnt+hit_cnt_group, MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
			if(scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_tunnel+=n_hit_result;
			}
			if(scan_ret >= MAAT_SCAN_OK)
			{
				n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
				request->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
	}
	if(logic && scan_ret >= MAAT_SCAN_OK)
	{
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TUNNEL_RULE", "ATTR_TUNNEL", ctx->result+hit_cnt+hit_cnt_group,
								       MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_tunnel+=n_hit_result;
		}
		if(scan_ret >= MAAT_SCAN_HALF_HIT)
		{
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			request->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);
			ctx->n_read=n_read;
			hit_path_cnt++;
		}
	}
	ctx->tunnel_attr_count--;
	request->merge_nth_scan_num = hit_path_cnt;
finish:
	return hit_cnt_tunnel;
}

static int app_id_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	size_t n_hit_result=0;
	int scan_ret=0, hit_cnt_app_id=0;
	struct maat_hit_object objects;
	struct app_id_dict *app_dict=NULL;

	app_dict = (struct app_id_dict*)maat_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], "APP_ID_DICT", (const char *)&(request->numeric), sizeof(long long));
	if(app_dict==NULL)
	{
		return 0;
	}

	memset(&objects, 0, sizeof(objects));
    uuid_copy(objects.object_uuid, app_dict->object_uuid);
	scan_ret=maat_scan_object(g_policy_rt->feather[vsys_id], "APP_ID_DICT", "ATTR_APP_ID", &objects, 1, ctx->result+hit_cnt+hit_cnt_app_id,
							   MAX_SCAN_RESULT-hit_cnt-hit_cnt_app_id, &n_hit_result, ctx->scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_app_id+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "APP_ID_DICT", "ATTR_APP_ID", ctx->result+hit_cnt+hit_cnt_app_id,
								   MAX_SCAN_RESULT-hit_cnt-hit_cnt_app_id, &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_app_id+=n_hit_result;
	}
	app_id_dict_free(app_dict);
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_app_id;
}

static int flag_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_flag=0;
	size_t n_hit_result=0;

	int flag=request->numeric;

	scan_ret=maat_scan_flag(g_policy_rt->feather[vsys_id], "TSG_OBJ_FLAG", "ATTR_FLAG",	flag, ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt, &n_hit_result, ctx->scan_mid);
	if(scan_ret==MAAT_SCAN_HIT)
	{
		hit_cnt_flag+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TSG_OBJ_FLAG", "ATTR_FLAG", ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt, &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_flag+=n_hit_result;
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_flag;
}

static int http_hdr_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_hdr=0;
	size_t n_hit_result=0;

	if(!request->string)
	{
		return hit_cnt_hdr;
	}

	const char *value = request->string;
	scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], get_table_name(request->attribute_name, vsys_id), request->attribute_name,
								value, strlen(value), ctx->result + hit_cnt, MAX_SCAN_RESULT - hit_cnt,
		 					    &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_hdr += n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], get_table_name(request->attribute_name, vsys_id), request->attribute_name, ctx->result + hit_cnt, MAX_SCAN_RESULT - hit_cnt,
                      				&n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_hdr += n_hit_result;
	}

	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_hdr;
}

enum ip_protocol_type
{
	PROCOCOL_ANY=-1,
	PROTOCOL_ICMP=1,
	PROCOCOL_TCP=6,
	PROCOCOL_UDP=17,
};

const char *get_object_uuid_by_protocol(int protocol)
{
	switch(protocol)
	{
		case PROCOCOL_ANY:
			return PROTOCOL_ANY_OBJECT_UUID;
		case PROTOCOL_ICMP:
			return PROTOCOL_ICMP_OBJECT_UUID;
		case PROCOCOL_TCP:
			return PROTOCOL_TCP_OBJECT_UUID;
		case PROCOCOL_UDP:
			return PROTOCOL_UDP_OBJECT_UUID;
		default:
			return NULL;
	}
}

static int protocol_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_protocol=0;

	const char *object_uuid=get_object_uuid_by_protocol(request->numeric);
	if(object_uuid != NULL)
	{
		scan_ret = scan_object(ctx, vsys_id, hit_cnt, (char *)object_uuid, "TSG_OBJ_IP_PROTOCOL", request->attribute_name);
		if(scan_ret > 0)
		{
			hit_cnt_protocol+=scan_ret;
		}
		n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
		request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
		ctx->n_read=n_read;
	}
	return hit_cnt_protocol;
}

static int ip_addr_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_ip=0;
	size_t n_hit_result=0;

	if (request->ip_addr->addrtype == ADDR_TYPE_IPV4)
	{
		if(0 == strcasecmp(request->attribute_name, "ATTR_SOURCE_IP") || 0 == strcasecmp(request->attribute_name, "ATTR_INTERNAL_IP"))
		{
			scan_ret = maat_scan_ipv4_port(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, request->ip_addr->v4->saddr, request->ip_addr->v4->source,
			 						      ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if(scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  	  &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
		}
		if(0 == strcasecmp(request->attribute_name, "ATTR_DESTINATION_IP") || 0 == strcasecmp(request->attribute_name, "ATTR_EXTERNAL_IP"))
		{
			scan_ret = maat_scan_ipv4_port(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, request->ip_addr->v4->daddr, request->ip_addr->v4->dest,
			 						       ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if(scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  	  &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
		}
		if(scan_ret >= MAAT_SCAN_OK)
		{
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
			ctx->n_read=n_read;
		}
	}
	if (request->ip_addr->addrtype == ADDR_TYPE_IPV6)
	{
		if(0 == strcasecmp(request->attribute_name, "ATTR_SOURCE_IP") || 0 == strcasecmp(request->attribute_name, "ATTR_INTERNAL_IP"))
		{
			scan_ret = maat_scan_ipv6_port(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, request->ip_addr->v6->saddr,request->ip_addr->v6->source,
									       ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  	  &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
		}
		if(0 == strcasecmp(request->attribute_name, "ATTR_DESTINATION_IP") || 0 == strcasecmp(request->attribute_name, "ATTR_EXTERNAL_IP"))
		{
			scan_ret = maat_scan_ipv6_port(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, request->ip_addr->v6->daddr, request->ip_addr->v6->dest,
									       ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TSG_OBJ_IP_ADDR", request->attribute_name, ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  	  &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
		}
		if(scan_ret >= MAAT_SCAN_OK)
		{
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
			ctx->n_read=n_read;
		}
	}
	return hit_cnt_ip;
}

static int ssl_extension_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_ssl=0;

	const char *object_uuid=(request->numeric == 1 ? BOOLEAN_TRUE_OBJECT_UUID : BOOLEAN_FLASE_OBJECT_UUID);
	scan_ret =scan_object(ctx, vsys_id, hit_cnt, (char *)object_uuid, "TSG_OBJ_BOOLEAN", request->attribute_name);
	if(scan_ret > 0)
	{
		hit_cnt_ssl += scan_ret;
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_ssl;
}

static int port_scan(struct request_object_list *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_port=0;
	size_t n_hit_result=0;
	int port = atoi(request->string);

	scan_ret=maat_scan_integer(g_policy_rt->feather[vsys_id], "TSG_OBJ_PORT", request->attribute_name, port, ctx->result+hit_cnt+hit_cnt_port,
							   MAX_SCAN_RESULT-hit_cnt-hit_cnt_port, &n_hit_result, ctx->scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_port+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], "TSG_OBJ_PORT", request->attribute_name, ctx->result+hit_cnt+hit_cnt_port,
								   MAX_SCAN_RESULT-hit_cnt-hit_cnt_port, &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_port+=n_hit_result;
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_port;
}

size_t policy_verify_scan(int vsys_id, int compile_table_id, struct request_object_list *request_object, struct policy_scan_ctx * ctx)
{
	size_t n_hit_result=0;
	int scan_ret=0, n_read;
	size_t hit_cnt = ctx->hit_cnt;

	int table_id = request_object->table_id;
	const char *value = request_object->string;

	switch (table_id)
	{
		case TSG_OBJ_SOURCE_ADDR:
		case TSG_OBJ_DESTINATION_ADDR:
		case TSG_OBJ_INTERNAL_ADDR:
		case TSG_OBJ_EXTERNAL_ADDR:
			if(request_object->ip_addr == NULL)
			{
				goto decide;
			}
			scan_ret = ip_entry_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			scan_ret = ip_addr_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_IP_PROTOCOL:
			scan_ret = protocol_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_SOURCE_PORT:
		case TSG_OBJ_DESTINATION_PORT:
		case TSG_OBJ_INTERNAL_PORT:
		case TSG_OBJ_EXTERNAL_PORT:
			scan_ret = port_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_TUNNEL_LEVEL:
			scan_ret = tunnel_level_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+= scan_ret;
			}
			goto decide;
		case TSG_OBJ_TUNNEL:
			struct ip_addr dest_ip, source_ip;
			ip_addr_to_address(request_object->ip_addr, &dest_ip, &source_ip);
			scan_ret = tunnel_scan(request_object, ctx, vsys_id, hit_cnt, request_object->ip_addr);
			if(scan_ret)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_APP_ID:
			scan_ret = app_id_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_FLAG:
			scan_ret = flag_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_HTTP_REQ_HDR:
		case TSG_OBJ_HTTP_RES_HDR:
			scan_ret = http_hdr_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_SSL_ECH:
		case TSG_OBJ_SSL_ESNI:
		case TSG_OBJ_SSL_NO_SNI:
			scan_ret = ssl_extension_scan(request_object, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+= scan_ret;
			}
			goto decide;
		default:
			break;
	}

	if(request_in_fqdn_cat(table_id))
	{
		scan_ret = get_fqdn_category_id(request_object, ctx, vsys_id, value, TSG_OBJ_DST_SERVER_FQDN, hit_cnt);
		if(scan_ret>0)
		{
			hit_cnt+=scan_ret;
		}
	}

	scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], get_table_name(request_object->attribute_name, vsys_id),request_object->attribute_name,
								value, strlen(value), ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt,
						 	    &n_hit_result, ctx->scan_mid);
	if(scan_ret==MAAT_SCAN_HIT)
	{
		hit_cnt+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], get_table_name(request_object->attribute_name, vsys_id),request_object->attribute_name,
								   ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt,&n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt+=n_hit_result;
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request_object->merge_nth_scan[request_object->merge_nth_scan_num] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
decide:
	ctx->hit_cnt = hit_cnt;
	return hit_cnt;
}

int http_get_int_param(cJSON* http_request, const char *key)
{
	int vsys_id=-1;

	cJSON *item = cJSON_GetObjectItem(http_request, key);
	if(item && item->type==cJSON_Number)
	{
		vsys_id = item->valueint;
	}
	return vsys_id;
}

char *http_get_string_param(cJSON* http_request, const char *key)
{
	char *param=NULL;

	cJSON *item = cJSON_GetObjectItem(http_request, key);
	if(item && item->type==cJSON_String)
	{
		param = item->valuestring;
	}
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

cJSON *get_library_search_query(const char *data, ssize_t data_len)
{
	int hit_library_cnt=0;

	cJSON* http_request = cJSON_Parse(data);
	if(http_request == NULL)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Failed to parse the request data.");
		return NULL;
	}

	cJSON *http_respone=cJSON_CreateObject();
	cJSON_AddNumberToObject(http_respone, "code", 200);
	cJSON_AddStringToObject(http_respone, "msg", "Success");

	cJSON *http_body = cJSON_CreateObject();
	cJSON_AddItemToObject(http_respone, "data", http_body);

	cJSON *hit_library=cJSON_CreateArray();
	cJSON_AddItemToObject(http_body, "hit_library", hit_library);

	int vsys_id = http_get_int_param(http_request, "vsys");
	if(vsys_id < 0)
	{
		cJSON_Delete(http_request);
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "invalid vsys_id");
		return NULL;
	}

	char *ip = http_get_string_param(http_request, "ip");
	if(ip)
	{
		struct ipaddr *ip_addr = ip_to_stream_addr(ip, 0, "0.0.0.0", 0, get_ip_type(ip), NULL, 0);
		hit_library_cnt=get_ip_entry_tag_ids(hit_library, vsys_id, ip_addr);
		ipaddr_free(ip_addr);
	}

	char *fqdn = http_get_string_param(http_request, "fqdn");
	if(fqdn)
	{
		hit_library_cnt=get_fqdn_entry_tag_ids(hit_library, vsys_id, fqdn);
	}

	if (hit_library_cnt >= 0)
	{
		cJSON_AddBoolToObject(http_respone, "success", true);
	}
	else
	{
		cJSON_AddBoolToObject(http_respone, "success", false);
	}
	cJSON_Delete(http_request);

	return http_respone;
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
	const char *attribute_name_map[] ={"ATTR_SOURCE_IP", "ATTR_DESTINATION_IP", "ATTR_TUNNEL", "ATTR_INTERNAL_IP", "ATTR_EXTERNAL_IP"};
	for(i = 0; i < sizeof(attribute_name_map)/sizeof(attribute_name_map[0]); i++)
	{
		if(0 == strcasecmp(attri_name, attribute_name_map[i]))
		{
			return i;
		}
	}
	return -1;
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

	if(strcasecmp(attributeName, "ATTR_IP_PROTOCOL") == 0)
	{
		log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] %s, protocol=%d", buff, *protocol);
		return NULL;
	}

	struct ipaddr *ip_addr = NULL;
	if(strcasecmp(attributeName, "ATTR_SOURCE_IP") == 0 || strcasecmp(attributeName, "ATTR_INTERNAL_IP") == 0 ||
	   strcasecmp(attributeName, "ATTR_TUNNEL") == 0)
	{
		ip_addr = ip_to_stream_addr(Ip, Port, "0.0.0.0", 0, addr_type, buff, protocol);
	}

	if(strcasecmp(attributeName, "ATTR_DESTINATION_IP") == 0 || strcasecmp(attributeName, "ATTR_EXTERNAL_IP") == 0)
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

static int get_attribute_from_json(struct request_object_list *request_object, cJSON* subchild)
{
	int xret = -1;
	const char *attribute_type=NULL;
	char buff[VERIFY_STRING_MAX*2], *p = NULL;
	cJSON* item = NULL, *attributeValue=NULL, *tunnelType_item=NULL;

	p = buff;
	item = cJSON_GetObjectItem(subchild, "attribute_value_type");
	if(item && item->type==cJSON_String)
	{
		attribute_type = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), "attribute_type = %s", attribute_type);
	}

	item = cJSON_GetObjectItem(subchild, "attribute_name");
	if(item && item->type==cJSON_String)
	{
		request_object->attribute_name = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", attribute_name = %s",request_object->attribute_name);

		request_object->table_id = protoco_field_type_str2idx(item->valuestring, buff, &p);
		if(request_object->table_id == __TSG_OBJ_MAX)
		{
			log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Get table id failed form table name:%s", item->valuestring);
			return xret;
		}
	}
	request_object->attributes=cJSON_Duplicate(subchild, 1);

	attributeValue = cJSON_GetObjectItem(subchild, "attribute_value");
	if(attributeValue == NULL || attributeValue->type!=cJSON_Object)
	{
		goto finish;
	}

	tunnelType_item = cJSON_GetObjectItem(attributeValue,"tunnel_type");
	if(tunnelType_item && tunnelType_item->type==cJSON_String)
	{
		request_object->tunnel_type=tunnelType_item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", tunnel_type=%s",request_object->tunnel_type);
	}

	if(0 == strcasecmp(attribute_type, "ip"))
	{
		request_object->ip_addr = get_ip_from_json(attributeValue, request_object->attribute_name, &(request_object->numeric), buff);
		goto end;
	}
	if(0 == strcasecmp(attribute_type, "port"))
	{
		request_object->string = get_port_from_json(attributeValue, &(request_object->numeric), buff);
		goto end;
	}

	item = cJSON_GetObjectItem(attributeValue,"district");
	if(item!=NULL)
	{
		request_object->district_value = item->valuestring;
		p += snprintf(p, sizeof(buff) - (p - buff), ", district = %s", request_object->district_value);
	}

	if(match_attributeType_in_numeric(attribute_type, request_object->table_id))
	{
		item = cJSON_GetObjectItem(attributeValue, "numeric");
		if(item && item->type==cJSON_Number)
		{
			request_object->numeric = item->valueint;
			p += snprintf(p, sizeof(buff) - (p - buff), ", content = %d", request_object->numeric);
		}
	}
	else
	{
		item = cJSON_GetObjectItem(attributeValue, "string");
		if(item!=NULL)
		{
			request_object->string = item->valuestring;
			p += snprintf(p, sizeof(buff) - (p - buff), ", content = %s", request_object->string);
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
	int cur_id=0, i=0, is_valid[MAX_REGEX_EXPRESS_NUM]={0};
	cJSON *regexstr_obj[MAX_REGEX_EXPRESS_NUM],*attributes=NULL;
	cJSON *item = NULL, *subchild = NULL;

	attributes = cJSON_GetObjectItem(verifylist_array_item, "verify_regex");
	if(attributes==NULL || attributes->type != cJSON_Array)
	{
		return -1;
	}

	for (subchild = attributes->child; subchild != NULL; subchild = subchild->next)
	{
		if(cur_id > MAX_REGEX_EXPRESS_NUM)
		{
			log_error(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Supports up to %d regular expression validations", MAX_REGEX_EXPRESS_NUM);
			break;
		}
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

	if(cur_id == 0)
	{
		log_error(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "validated regular expression is empty");
	}

	return 1;
}

static void get_count_form_attributeName(struct policy_scan_ctx *ctx, cJSON *subchild)
{
	cJSON *item = NULL;

	item = cJSON_GetObjectItem(subchild, "attribute_name");
	if(item && item->type==cJSON_String)
	{
		if(0 == strcasecmp(item->valuestring, "ATTR_TUNNEL"))
		{
			ctx->tunnel_attr_count++;
		}
	}
	return;
}

UT_icd ut_object_id_icd = {sizeof(struct request_object_list), NULL, NULL, NULL};

int get_query_result_policy(cJSON *verifylist_array_item, cJSON *http_body, int vsys_id, int thread_id)
{
	int hit_cnt = 0, xret =0;
	cJSON *item = NULL, *subchild = NULL, *attributes=NULL;
	struct request_object_list *request_object=NULL;
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

	verify_policy->vsys_id = vsys_id;
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] vsys_id= %d", verify_policy->vsys_id);

	item = cJSON_GetObjectItem(verifylist_array_item,"verify_session");
	if(item == NULL || item->type!=cJSON_Object)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "get verify_session attribute failed:%s", item->valuestring);
		goto free;
	}

	attributes = cJSON_GetObjectItem(item,"attributes");
	if(attributes && attributes->type==cJSON_Array)
	{
		struct policy_scan_ctx *ctx = policy_scan_ctx_new(thread_id, verify_policy->vsys_id, verify_policy->compile_table_id);

		for (subchild = attributes->child; subchild != NULL; subchild = subchild->next)
		{
			get_count_form_attributeName(ctx, subchild);
		}

		utarray_new(verify_policy->ut_array_by_object, &ut_object_id_icd);

		for (subchild = attributes->child; subchild != NULL; subchild = subchild->next)
		{
			struct request_object_list request_object;
			memset(&request_object, 0, sizeof(request_object));

			xret = get_attribute_from_json(&request_object, subchild);
			if (xret < 0)
			{
				goto free;
			}
			hit_cnt = policy_verify_scan(verify_policy->vsys_id, verify_policy->compile_table_id, &request_object, ctx);
			if(match_ip_attribute_name(request_object.attribute_name) >= 0)
			{
				ipaddr_free(request_object.ip_addr);
			}
			utarray_push_back(verify_policy->ut_array_by_object, &request_object);
		}

		http_hit_policy_list(verify_policy, hit_cnt, http_body, ctx);

		cJSON *verfifySession = cJSON_CreateObject();
		cJSON_AddItemToObject(http_body, "verify_session", verfifySession);
		cJSON *attributes=cJSON_CreateArray();
		cJSON_AddItemToObject(verfifySession, "attributes", attributes);

		while ((request_object=(struct request_object_list *)utarray_next(verify_policy->ut_array_by_object, request_object)) != NULL)
		{
			http_get_scan_status(request_object, verify_policy->compile_table_id, attributes, ctx);
		}
		policy_scan_ctx_free(ctx);
		utarray_free(verify_policy->ut_array_by_object);
	}

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

	int vsys_id=0;
	item = cJSON_GetObjectItem(http_request, "vsys");
	if(item && item->type==cJSON_Number)
	{
		vsys_id = item->valueint;
	}

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
				hit_cnt = get_query_result_policy(subitem, http_body, vsys_id, thread_id);
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

static struct maat *create_maat_feather(const char * instance_name, const char * profile, const char * section, int max_thread, char *log_path, int db_index)
{
	struct maat *target=NULL;
	int input_mode = 0, maat_perf_on = 0, log_level=0;
	int ret = 0, maat_stat_on = 0, effect_interval = 60;
	char table_info[VERIFY_STRING_MAX] = {0}, inc_cfg_dir[VERIFY_STRING_MAX] = {0}, ful_cfg_dir[VERIFY_STRING_MAX] = {0};
	char json_cfg_file[VERIFY_STRING_MAX] = {0}, maat_stat_file[VERIFY_PATH_MAX] = {0};
	char redis_ip[VERIFY_STRING_MAX] = {0}, redis_port_range[VERIFY_STRING_MAX] = {0};
	char accept_tags[VERIFY_STRING_MAX] = {0}, maat_stat_db_file[VERIFY_PATH_MAX + 12] = {0};
	int redis_port_begin=0, redis_port_end=0;
	int redis_port_select=0;

	MESA_load_profile_int_def(profile, section, "maat_input_mode", &(input_mode), 0);
	MESA_load_profile_int_def(profile, section, "perf_switch", &(maat_perf_on), 0);
	MESA_load_profile_int_def(profile, section, "stat_switch", &(maat_stat_on), 1);

	MESA_load_profile_string_def(profile, section, "table_info", table_info, sizeof(table_info), "");
	MESA_load_profile_string_def(profile, section, "json_cfg_file", json_cfg_file, sizeof(json_cfg_file), "");
	MESA_load_profile_string_def(profile, section, "maat_redis_server", redis_ip, sizeof(redis_ip), "");
	MESA_load_profile_string_def(profile, section, "maat_redis_port_range", redis_port_range, sizeof(redis_port_range), "6379");
	MESA_load_profile_string_def(profile, section, "accept_tags", accept_tags, sizeof(accept_tags), "");
	MESA_load_profile_int_def(profile, section, "log_level", &(log_level), LOG_LEVEL_FATAL);

	ret=sscanf(redis_port_range,"%d-%d", &redis_port_begin, &redis_port_end);
	if(ret==1)
	{
		redis_port_select=redis_port_begin;
	}
	else if(ret==2)
	{
		srand(time(NULL));
		redis_port_select=redis_port_begin+rand()%(redis_port_end-redis_port_begin);
	}
	else
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Invalid redis port range %s, MAAT init failed.", redis_port_range);
	}
	MESA_load_profile_string_def(profile, section, "inc_cfg_dir", inc_cfg_dir, sizeof(inc_cfg_dir), "");
	MESA_load_profile_string_def(profile, section, "full_cfg_dir", ful_cfg_dir, sizeof(ful_cfg_dir), "");
	MESA_load_profile_int_def(profile, section, "effect_interval_s", &(effect_interval), 60);

	effect_interval *= 1000;//convert s to ms
	assert(strlen(inc_cfg_dir) != 0 || strlen(ful_cfg_dir) != 0 || strlen(redis_ip)!=0 || strlen(json_cfg_file)!=0);

    struct maat_options *opts = maat_options_new();
	maat_options_set_logger(opts, log_path, (enum log_level)log_level);
	maat_options_set_instance_name(opts, instance_name);
	switch (input_mode)
	{
		case MAAT_INPUT_JSON:
			maat_options_set_json_file(opts, json_cfg_file);
			break;
		case MAAT_INPUT_REDIS:
			maat_options_set_redis(opts, redis_ip, redis_port_select, db_index);
			break;
		default: log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Invalid MAAT Input Mode: %d.", input_mode);
			goto error_out;
			break;
	}
	maat_options_set_foreign_cont_dir(opts, "./verify_policy_files");
	maat_options_set_caller_thread_number(opts, max_thread);
	maat_options_set_hit_path_enabled(opts);

	if(maat_perf_on)
	{
		maat_options_set_perf_on(opts);
	}

	MESA_load_profile_string_def(profile, section, "stat_file", maat_stat_file, sizeof(maat_stat_file), "");
	if (strlen(maat_stat_file) > 0 && maat_stat_on)
	{
		maat_options_set_stat_on(opts);
		snprintf(maat_stat_db_file, VERIFY_PATH_MAX+12, "%s.%d", maat_stat_file, db_index);
        maat_options_set_stat_file(opts, maat_stat_db_file);
	}

	target = maat_new(opts, table_info);
	if (!target)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "%s MAAT init failed.", __FUNCTION__);
		goto error_out;
	}

	log_info(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "%s:%s", "Maat Redis Ip", redis_ip);
	log_info(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "%s:%s", "Maat Redis Port", redis_port_range);
	log_info(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "%s:%d", "Maat Redis_db_index", db_index);

    maat_options_free(opts);
	return target;

error_out:
    maat_options_free(opts);
	return NULL;
}

int maat_complie_plugin_table_init(int vsys_id)
{
	int ret=0;
	const char *plugin_table_name_map[] = {"SECURITY_RULE_PLUGIN", "PXY_CTRL_RULE_PLUGIN", "TRAFFIC_SHAPING_RULE_PLUGIN",
											"SERVICE_CHAINING_RULE_PLUGIN", "PXY_INTERCEPT_RULE_PLUGIN", "STATISTICS_COMPILE_PLUGIN",
											"MONITOR_RULE_PLUGIN", "DOS_PROTECTION_RULE_PLUGIN", "TUNNEL_RULE_PLUGIN"};
	for(int i = 0; i < PXY_TABLE_DEFENCE; i++)
	{
		const char * table_name = plugin_table_name_map[i];
		ret = maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, compile_table_new_cb, compile_free_data, compile_dup_data, 0,NULL);
		if(ret<0)
		{
			continue;
		}
	}
	return ret;
}

void verify_reload_loglevel()
{
	int vsys_id=0;
	int load_vsys_num=0, log_level=0;
	const char * profile_path = "./conf/verify_policy.conf";

	MESA_load_profile_int_def(profile_path, "SYSTEM", "log_level", &log_level, LOG_FATAL);
	log_options_set_level(g_verify_proxy->logger, log_level);

	MESA_load_profile_int_def(profile_path, "MAAT", "load_vsys_num", &(load_vsys_num), 255);
	MESA_load_profile_int_def(profile_path, "MAAT", "log_level", &(log_level), LOG_LEVEL_FATAL);

	for(vsys_id=0; vsys_id < load_vsys_num; vsys_id++)
	{
		if(g_policy_rt->feather[vsys_id] != NULL)
		{
			maat_reload_log_level(g_policy_rt->feather[vsys_id], (enum log_level)log_level);
		}
	}
}

int verify_policy_table_init(struct verify_policy * verify, const char* profile_path)
{
	int ret = -1; int vsys_id=0;
	int load_vsys_num=0, load_start_vsys=0;
	char log_path[VERIFY_PATH_MAX] = {0};

	g_policy_rt = ALLOC(struct verify_policy_rt, 1);
	g_policy_rt->local_logger = verify->logger;
	g_policy_rt->thread_num = verify->nr_work_threads;

	MESA_load_profile_int_def(profile_path, "MAAT", "load_vsys_num", &(load_vsys_num), 255);
	MESA_load_profile_int_def(profile_path, "MAAT", "load_start_vsys", &(load_start_vsys), 0);
	load_vsys_num = load_vsys_num > VSYS_ID_MAX ? VSYS_ID_MAX : load_vsys_num;
	load_start_vsys = load_start_vsys > load_vsys_num ? 0 : load_start_vsys;

	for(vsys_id=load_start_vsys; vsys_id < load_vsys_num; vsys_id++)
	{
		memset(log_path, 0, sizeof(log_path));
		snprintf(log_path, sizeof(log_path), "logs/log/maat.db%d.log", vsys_id);
		g_policy_rt->feather[vsys_id] = create_maat_feather("static", profile_path, "MAAT", g_policy_rt->thread_num, log_path, vsys_id);
		if (!g_policy_rt->feather[vsys_id])
		{
			goto error_out;
		}

		ret = maat_complie_plugin_table_init(vsys_id);
		if(ret<0)
		{
			goto error_out;
		}

		ret = maat_plugin_table_ex_init(PROFILE_APP_DI_DICT, vsys_id, app_dict_table_new_cb, app_dict_table_free_cb, app_dict_table_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}

		ret = maat_plugin_table_ex_init(PROFILE_FQDN_ENTRY, vsys_id, fqdn_entry_new_cb, library_entry_free_cb, library_entry_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}
		ret = maat_plugin_table_ex_init(PROFILE_IP_ADDR_ENTRY, vsys_id, fqdn_entry_new_cb, library_entry_free_cb, library_entry_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}
		ret = maat_plugin_table_ex_init(PROFILE_LIBRARY_TAG, vsys_id, library_tag_new_cb, library_tag_free_cb, library_tag_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}
		ret = maat_plugin_table_ex_init(PROFILE_ATTRIBUTE_DICT, vsys_id, attribute_dict_new_cb, attribute_dict_free_cb, attribute_dict_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}
	}
	ret = 0;
error_out:
	return ret;
}

void verify_policy_table_free(const char* profile_path)
{
	int load_vsys_num=0, load_start_vsys=0;

	MESA_load_profile_int_def(profile_path, "MAAT", "load_vsys_num", &(load_vsys_num), 255);
	MESA_load_profile_int_def(profile_path, "MAAT", "load_start_vsys", &(load_start_vsys), 0);
	load_vsys_num = load_vsys_num > VSYS_ID_MAX ? VSYS_ID_MAX : load_vsys_num;
	load_start_vsys = load_start_vsys > load_vsys_num ? 0 : load_start_vsys;

	for(int vsys_id=load_start_vsys; vsys_id < load_vsys_num; vsys_id++)
	{
		if(g_policy_rt->feather[vsys_id])
		{
			maat_free(g_policy_rt->feather[vsys_id]);
		}
	}
	FREE(&g_policy_rt);

	return;
}

