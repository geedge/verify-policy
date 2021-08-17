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

#include <MESA/Maat_rule.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/stream.h>

#include <cjson/cJSON.h>

#include "verify_policy.h"
#include "verify_policy_utils.h"
#include "verify_policy_logging.h"

#define	MAX_SCAN_RESULT				16

enum pangu_action
{
	PG_ACTION_NONE = 0x00,
	PG_ACTION_MONIT = 0x01,
	PG_ACTION_INTERCEPT = 0x02,    /* N/A */
	PG_ACTION_ACTIVE_DEFENCE = 0x04,
	PG_ACTION_WANNAT = 0x08,
	PG_ACTION_REJECT = 0x10,
	PG_ACTION_MANIPULATE = 0x30,
	PG_ACTION_INLINE_DEVICE = 0x60,
	PG_ACTION_WHITELIST = 0x80,
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
	POLICY_ASN_USER_DEFINED,
	POLICY_ASN_BUILT_IN,
	POLICY_LOCATION_USER_DEFINED,
	POLICY_LOCATION_BUILT_IN,
	POLICY_FQDN_CAT_USER_DEFINED,
	POLICY_FQDN_CAT_BUILT_IN,
	POLICY_PROFILE_TABLE_MAX,
};

struct ip_data_table
{
	int profile_id;

	int ref_cnt;

	char *asn;
	char *organization;

	char *country_full;
	char *province_full;
	char *city_full;

	pthread_mutex_t lock;
};

struct http_field_name
{
	const char * field_name;
	enum http_std_field field_id;
};

struct ip_data_ctx
{
	char *asn_client;
	char *asn_server;
	char *organization_client;
	char *organization_server;
	char *location_client;
	char *location_server;
};

struct fqdn_category_t
{
	int ref_cnt;
	unsigned int category_id;
	int match_method;
	char fqdn[VERIFY_ARRAY_MAX];

	pthread_mutex_t lock;
};

struct pangu_http_ctx
{
	enum pangu_action action;
	char * action_para;
	scan_status_t scan_mid;
	stream_para_t sp;
	size_t hit_cnt;
	struct Maat_rule_t result[MAX_SCAN_RESULT];
	size_t n_enforce;
	struct Maat_rule_t * enforce_rules;
	int n_read;
	struct Maat_hit_path_t hit_path[2048];

	struct ip_data_ctx ip_ctx;
	int thread_id;
};

struct pangu_rt
{
	Maat_feather_t maat[__SCAN_POLICY_MAX];
	Maat_feather_t dyn_maat;
	int subscriber_id_table_id;
	void * local_logger;
	int log_level;
	int thread_num;
	int plolicy_table_id[POLICY_PROFILE_TABLE_MAX];
	int scan_table_id[__SCAN_POLICY_MAX][__SECURITY_TABLE_MAX];
};
struct pangu_rt * g_pangu_rt;

#define MAAT_INPUT_JSON			0
#define MAAT_INPUT_REDIS    	1
#define MAAT_INPUT_FILE        	2

void * pangu_http_ctx_new(unsigned int thread_id)
{
	struct pangu_http_ctx * ctx = ALLOC(struct pangu_http_ctx, 1);
	ctx->scan_mid = NULL;
	ctx->thread_id = (int) thread_id;
	return (void *)ctx;
}

void pangu_http_ctx_free(void * pme)
{
	struct pangu_http_ctx * ctx = (struct pangu_http_ctx *) pme;

	FREE(&ctx->enforce_rules);
	Maat_clean_status(&(ctx->scan_mid));
	ctx->scan_mid = NULL;

	struct ip_data_ctx *ip_ctx = &ctx->ip_ctx;
	if(ip_ctx->asn_client)
		FREE(&ip_ctx->asn_client);
	if(ip_ctx->asn_server)
		FREE(&ip_ctx->asn_server);
	if(ip_ctx->organization_client)
		FREE(&ip_ctx->organization_client);
	if(ip_ctx->organization_server)
		FREE(&ip_ctx->organization_server);
	if(ip_ctx->location_client)
		FREE(&ip_ctx->location_client);
	if(ip_ctx->location_server)
		FREE(&ip_ctx->location_server);
	if(ctx->sp)
	{
		Maat_stream_scan_string_end(&(ctx->sp));
	}
	FREE(&ctx);
}

static int pangu_action_weight[__PG_ACTION_MAX] = {0};
void __pangu_action_weight_init()  __attribute__((constructor, used));
void __pangu_action_weight_init()
{
	pangu_action_weight[PG_ACTION_NONE] = 0;
	pangu_action_weight[PG_ACTION_MONIT] = 1;
	pangu_action_weight[PG_ACTION_INTERCEPT] = 2;
	pangu_action_weight[PG_ACTION_MANIPULATE] = 3;
	pangu_action_weight[PG_ACTION_REJECT] = 4;
	pangu_action_weight[PG_ACTION_WHITELIST] = 5;
}

static inline int action_cmp(enum pangu_action a1, enum pangu_action a2)
{
	return pangu_action_weight[a1] - pangu_action_weight[a2];
}

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

void ip_asn_table_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int addr_type;
	int ret=0,profile_id=0,is_valid=0;
	char start_ip[40], end_ip[40],asn[40]={0};
	char organization[VERIFY_ARRAY_MAX];

	ret=sscanf(table_line, "%d\t%d\t%s\t%s\t%s\t%s\t%d", &profile_id, &addr_type, start_ip, end_ip, asn, organization, &is_valid);
	if(ret!=7)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Policy table parse ip ASN failed, ret:%d, %s", ret, table_line);
		return;
	}
	verify_unescape(organization);

	struct ip_data_table* ip_asn=ALLOC(struct ip_data_table, 1);
	memset(ip_asn, 0, sizeof(struct ip_data_table));
	ip_asn->profile_id=profile_id;
	ip_asn->asn=strdup(asn);
	ip_asn->organization=strdup(organization);
	ip_asn->ref_cnt=1;
	pthread_mutex_init(&(ip_asn->lock), NULL);

	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Policy table add success %d", profile_id);
	*ad = ip_asn;
}

void ip_location_table_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int ret=0,profile_id=0,is_valid=0;
	int geoname_id=0, addr_type=0;
	double latitude, longitude, coords;
	char language[40], start_ip[40], end_ip[40];
	char continent_abbr[VERIFY_ARRAY_MAX],continent_full[VERIFY_ARRAY_MAX];
	char country_abbr[VERIFY_ARRAY_MAX],province_abbr[VERIFY_ARRAY_MAX], time_zone[VERIFY_ARRAY_MAX];
	char country_full[VERIFY_ARRAY_MAX],province_full[VERIFY_ARRAY_MAX], city_full[VERIFY_ARRAY_MAX];

	ret=sscanf(table_line, "%d\t%d\t%d\t%s\t%s\t%lf\t%lf\t%lf\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d", &profile_id,&geoname_id,
			   &addr_type, start_ip,end_ip,&latitude,&longitude,&coords,language,
			   continent_abbr,continent_full, country_abbr,country_full,province_abbr,province_full,
			   city_full,time_zone,&is_valid);

	if(ret!=18)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Policy table parse ip location failed, ret:%d, %s", ret, table_line);
		return;
	}
	verify_unescape(continent_full);
	verify_unescape(country_full);
	verify_unescape(province_full);
	verify_unescape(city_full);

	struct ip_data_table* ip_asn=ALLOC(struct ip_data_table, 1);
	memset(ip_asn, 0, sizeof(struct ip_data_table));
	ip_asn->profile_id=profile_id;
	ip_asn->country_full=strdup(country_full);
	ip_asn->province_full=strdup(province_full);
	ip_asn->city_full=strdup(city_full);
	ip_asn->ref_cnt=1;
	pthread_mutex_init(&(ip_asn->lock), NULL);
	mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Policy table add success %d", profile_id);

	*ad = ip_asn;
}

void ip_table_dup_cb(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	struct ip_data_table* ip_asn=(struct ip_data_table*)(*from);
	pthread_mutex_lock(&(ip_asn->lock));
	ip_asn->ref_cnt++;
	pthread_mutex_unlock(&(ip_asn->lock));
	*to=ip_asn;
}

void ip_table_free_cb(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}
	struct ip_data_table* ip_asn=(struct ip_data_table*)(*ad);
	pthread_mutex_lock(&(ip_asn->lock));
	ip_asn->ref_cnt--;
	if(ip_asn->ref_cnt>0)
	{
		pthread_mutex_unlock(&(ip_asn->lock));
		return;
	}
	pthread_mutex_unlock(&(ip_asn->lock));
	pthread_mutex_destroy(&(ip_asn->lock));

	if(ip_asn->asn)	FREE(&ip_asn->asn);
	if(ip_asn->organization) FREE(&ip_asn->organization);
	if(ip_asn->country_full) FREE(&ip_asn->country_full);
	if(ip_asn->province_full) FREE(&ip_asn->province_full);
	if(ip_asn->city_full) FREE(&ip_asn->city_full);

	FREE(&ip_asn);
	*ad=NULL;
	return;
}

void ip_table_free(struct ip_data_table* ip_asn)
{
	ip_table_free_cb(0, (void **)&ip_asn, 0, NULL);
}

const char *table_name_map[] = {"TSG_IP_ASN_USER_DEFINED",
								"TSG_IP_ASN_BUILT_IN",
								"TSG_IP_LOCATION_USER_DEFINED",
								"TSG_IP_LOCATION_BUILT_IN",
								"TSG_FQDN_CATEGORY_USER_DEFINED",
								"TSG_FQDN_CATEGORY_BUILT_IN"};

int maat_fqdn_cat_table_init(int profile_idx,
							 Maat_plugin_EX_new_func_t* new_func,
							 Maat_plugin_EX_free_func_t* free_func,
							 Maat_plugin_EX_dup_func_t* dup_func)
{
	int table_id=0, ret=0;

	const char *table_name = table_name_map[profile_idx];
	table_id=g_pangu_rt->plolicy_table_id[profile_idx]=Maat_table_register(g_pangu_rt->maat[PXY_TABLE_SECURITY], table_name);
	if(table_id >= 0)
	{
		ret=Maat_fqdn_plugin_EX_register(g_pangu_rt->maat[PXY_TABLE_SECURITY], table_id, new_func, free_func, dup_func,
										0, NULL);
		return ret;
	}
	mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Register fqdn cat table %s failed.", table_name);
	return -1;
}

int maat_ip_table_init(int profile_idx,
					   Maat_plugin_EX_free_func_t* free_func,
					   Maat_plugin_EX_dup_func_t* dup_func)
{
	int table_id=0;

	Maat_plugin_EX_new_func_t *new_func[] = {
			[POLICY_ASN_USER_DEFINED] = ip_asn_table_new_cb,
			[POLICY_ASN_BUILT_IN] = ip_asn_table_new_cb,
			[POLICY_LOCATION_USER_DEFINED] = ip_location_table_new_cb,
			[POLICY_LOCATION_BUILT_IN] = ip_location_table_new_cb,
	};

	const char *table_name = table_name_map[profile_idx];
	table_id=g_pangu_rt->plolicy_table_id[profile_idx]=Maat_table_register(g_pangu_rt->maat[PXY_TABLE_SECURITY], table_name);
	if(table_id >= 0)
	{
		table_id=Maat_ip_plugin_EX_register(g_pangu_rt->maat[PXY_TABLE_SECURITY], table_id, new_func[profile_idx], free_func, dup_func,
									   0, NULL);
		return 0;
	}
	mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Register table %s failed.", table_name);
	return -1;
}

void fqdn_cat_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	struct fqdn_category_t *fqdn_cat=(struct fqdn_category_t *)(*from);
	pthread_mutex_lock(&(fqdn_cat->lock));
	fqdn_cat->ref_cnt++;
	pthread_mutex_unlock(&(fqdn_cat->lock));
	*to=fqdn_cat;

	return;
}

void fqdn_cat_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int ret=0,id=0,is_valid=0;

	struct fqdn_category_t *fqdn_cat = ALLOC(struct fqdn_category_t, 1);

	ret=sscanf(table_line, "%d\t%u\t%s\t\t%d\t%d",&id, &fqdn_cat->category_id, fqdn_cat->fqdn, &fqdn_cat->match_method, &is_valid);
	if(ret!=5)
	{
		FREE(&fqdn_cat);
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Parse fqdn category failed, ret: %d table_id: %d table_line: %s", ret, table_id, table_line);
		return;
	}
	fqdn_cat->ref_cnt=1;
	pthread_mutex_init(&(fqdn_cat->lock), NULL);

	*ad=(MAAT_PLUGIN_EX_DATA)fqdn_cat;
	return;
}

void fqdn_cat_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}

	struct fqdn_category_t *fqdn_cat=(struct fqdn_category_t *)(*ad);
	pthread_mutex_lock(&(fqdn_cat->lock));
	fqdn_cat->ref_cnt--;
	if(fqdn_cat->ref_cnt>0)
	{
		pthread_mutex_unlock(&(fqdn_cat->lock));
		return;
	}
	pthread_mutex_unlock(&(fqdn_cat->lock));
	pthread_mutex_destroy(&(fqdn_cat->lock));

	FREE(&fqdn_cat);
	*ad=NULL;
	return;
}

void fqdn_cat_table_free(struct fqdn_category_t *fqdn_cat)
{
	fqdn_cat_free_data(0, (void **)&fqdn_cat, 0, NULL);
}

#if 0
static enum pangu_action decide_ctrl_action(const struct Maat_rule_t * hit_rules, size_t n_hit,
	struct Maat_rule_t ** enforce_rules, size_t * n_enforce)
{
	size_t n_monit = 0, exist_enforce_num = 0, i = 0;
	const struct Maat_rule_t * prior_rule = hit_rules;
	struct Maat_rule_t monit_rule[n_hit];
	enum pangu_action prior_action = PG_ACTION_NONE;

	for (i = 0; i < n_hit && i < MAX_SCAN_RESULT ; i++)
	{
		unsigned char __expand_action = (unsigned char) hit_rules[i].action;
		enum pangu_action __action = (enum pangu_action) __expand_action;
		if (__action == PG_ACTION_MONIT)
		{
			memcpy(monit_rule + n_monit, hit_rules + i, sizeof(struct Maat_rule_t));
			n_monit++;
			break;
		}
	}
	i = (i == 0) ? 1 : 0;

	prior_action = (enum pangu_action)hit_rules[i].action;
	prior_rule = hit_rules + i;

	exist_enforce_num = *n_enforce;
	if (prior_action == PG_ACTION_MONIT)
	{
		*n_enforce += n_monit;
	}
	else
	{
		*n_enforce += n_monit + 1;
	}

	*enforce_rules = (struct Maat_rule_t *) realloc(*enforce_rules, sizeof(struct Maat_rule_t) * (*n_enforce));
	if (prior_action == PG_ACTION_MONIT)
	{
		memcpy(*enforce_rules + exist_enforce_num, monit_rule, n_monit * sizeof(struct Maat_rule_t));
	}
	else
	{
		memmove(*enforce_rules+1, *enforce_rules, exist_enforce_num*sizeof(struct Maat_rule_t));
		memcpy(*enforce_rules, prior_rule, sizeof(struct Maat_rule_t));
		memcpy(*enforce_rules + exist_enforce_num + 1, monit_rule, n_monit * sizeof(struct Maat_rule_t));
	}

	return prior_action;
}
#endif

static enum pangu_action decide_ctrl_action(enum verify_policy_type policy_type, const struct Maat_rule_t * hit_rules, size_t n_hit, struct Maat_rule_t ** enforce_rules, size_t * n_enforce)
{
	size_t n_monit = 0, exist_enforce_num = 0, i = 0;
	const struct Maat_rule_t * prior_rule = hit_rules;
	struct Maat_rule_t monit_rule[n_hit];
	enum pangu_action prior_action = PG_ACTION_NONE;

	for (i = 0; i < n_hit && i<MAX_SCAN_RESULT; i++)
	{
		unsigned char __expand_action = (unsigned char) hit_rules[i].action;
		enum pangu_action __action = (enum pangu_action) __expand_action;

		if (__action == PG_ACTION_MONIT)
		{
			memcpy(monit_rule + n_monit, hit_rules + i, sizeof(struct Maat_rule_t));
			n_monit++;
		}
		if (action_cmp(__action, prior_action) > 0)
		{
			prior_rule = hit_rules + i;
			prior_action = __action;
		}
		else if (action_cmp(__action, prior_action) == 0)
		{
			if (hit_rules[i].config_id > prior_rule->config_id)
			{
				prior_rule = hit_rules + i;
			}
		}
		else
		{
			continue;
		}
	}

	if (prior_action == PG_ACTION_WHITELIST)
	{
		if(*n_enforce==0)
		{
			*enforce_rules=ALLOC(struct Maat_rule_t, 1);
		}
		*enforce_rules[0]=*prior_rule;
		*n_enforce=1;
		return PG_ACTION_WHITELIST;
	}

	size_t monit_enable=1;
	if(policy_type == PXY_TABLE_SECURITY && n_monit != n_hit)
	{
		monit_enable=0;
	}

	exist_enforce_num = *n_enforce;
	if (prior_action == PG_ACTION_MONIT)
	{
		*n_enforce += n_monit;
	}
	else
	{
		*n_enforce += n_monit + 1;
	}

	*enforce_rules = (struct Maat_rule_t *) realloc(*enforce_rules, sizeof(struct Maat_rule_t) * (*n_enforce));
	if (prior_action == PG_ACTION_MONIT && monit_enable)
	{
		memcpy(*enforce_rules + exist_enforce_num, monit_rule, n_monit * sizeof(struct Maat_rule_t));
	}
	else
	{
		memmove(*enforce_rules+1, *enforce_rules, exist_enforce_num*sizeof(struct Maat_rule_t));
		memcpy(*enforce_rules, prior_rule, sizeof(struct Maat_rule_t));
		if(monit_enable)
		{
			memcpy(*enforce_rules + exist_enforce_num + 1, monit_rule, n_monit * sizeof(struct Maat_rule_t));
		}
	}
	return prior_action;
}

int http_table_in_fqdn(int protocol_field, int policy_type)
{

	if(policy_type == PXY_TABLE_SECURITY &&(protocol_field == PXY_SECURITY_HTTP_FQDN ||
	   protocol_field == PXY_SECURITY_HTTPS_SNI || protocol_field==PXY_SECURITY_HTTPS_CN || protocol_field==PXY_SECURITY_HTTPS_SAN ||
       protocol_field==PXY_SECURITY_DNS_QNAME || protocol_field == PXY_SECURITY_QUIC_SNI))
	{
		return 1;
	}

	if(policy_type == PXY_TABLE_MANIPULATION &&(protocol_field == PXY_CTRL_HTTP_FQDN ||
			protocol_field == PXY_CTRL_DOH_QNAME || protocol_field==PXY_CTRL_DOH_HOST))
	{
		return 1;
	}

	return 0;
}

void http_get_fqdn_cat_id(struct verify_policy_query_obj *query_obj, int type, cJSON *attributeObj)
{
	int i=0;
	cJSON *sniCategory=NULL;

	if(!http_table_in_fqdn(query_obj->protocol_field, type))
	{
		return;
	}

	sniCategory=cJSON_CreateArray();
	cJSON_AddItemToObject(attributeObj, "sniCategory", sniCategory);

	cJSON *fqdnObj=NULL;
	for(i=0; i<query_obj->category_user_num; i++)
	{
		fqdnObj=cJSON_CreateObject();
		cJSON_AddItemToArray(sniCategory, fqdnObj);
		cJSON_AddNumberToObject(fqdnObj, "categoryId", query_obj->category_id_user[i]);
	}

	for(i=0; i<query_obj->category_built_num; i++)
	{
		fqdnObj=cJSON_CreateObject();
		cJSON_AddItemToArray(sniCategory, fqdnObj);
		cJSON_AddNumberToObject(fqdnObj, "categoryId", query_obj->category_id_built[i]);
	}
}

void http_get_location_status(cJSON *attributes, cJSON *attributeObj, struct ip_data_ctx *ip_ctx )
{
	int i=0;
	cJSON* item=NULL; char *attri_name=NULL;
	cJSON* ipAsn=NULL;

	item = cJSON_GetObjectItem(attributeObj, "attributeType");
	if(item == NULL || item->type!=cJSON_String || strcasecmp(item->valuestring, "ip") != 0)
	{
		return;
	}
	item = cJSON_GetObjectItem(attributeObj, "attributeName");
	if(item && item->type==cJSON_String)
	{
		attri_name = item->valuestring;
		if(strcasecmp(attri_name, "source") == 0)
		{
			cJSON_AddStringToObject(attributeObj, "ipGeoLocation",ip_ctx->location_client);

			ipAsn=cJSON_CreateArray();
			cJSON_AddItemToObject(attributeObj, "ipAsn", ipAsn);
			cJSON *ipAsnObj=NULL;
			for(i=0; i< 1; i++)
			{
				ipAsnObj=cJSON_CreateObject();
				cJSON_AddItemToArray(ipAsn, ipAsnObj);
				cJSON_AddStringToObject(ipAsnObj, "asNumber", ip_ctx->asn_client);
				cJSON_AddStringToObject(ipAsnObj, "organization", ip_ctx->organization_client);
			}
		}
		if(strcasecmp(attri_name, "destination") == 0)
		{
			cJSON_AddStringToObject(attributeObj, "ipGeoLocation",ip_ctx->location_server);

			ipAsn=cJSON_CreateArray();
			cJSON_AddItemToObject(attributeObj, "ipAsn", ipAsn);
			cJSON *ipAsnObj=NULL;
			for(i=0; i< 1; i++)
			{
				ipAsnObj=cJSON_CreateObject();
				cJSON_AddItemToArray(ipAsn, ipAsnObj);
				cJSON_AddStringToObject(ipAsnObj, "asNumber", ip_ctx->asn_server);
				cJSON_AddStringToObject(ipAsnObj, "organization", ip_ctx->organization_server);
			}
		}
	}
	return;
}


/*In the case of multiple hits, the hit path is append behavior to obtain the last hit path force***/
int http_hit_policy_match(int result_config[], int cnt, int config)
{
	int i = 0;

	for(i=0; i<cnt; i++)
	{
		if(result_config[i] == config)
		{
			return 1;
		}
	}
	return 0;
}

void http_get_scan_status(struct verify_policy_query_obj *query_obj, int type, cJSON *attributes, cJSON  *data_obj, void *pme)
{
	int i=0, j=0, k=0;
	int result_hit_nth[MAX_SCAN_RESULT] = {-1};
	cJSON *attributeObj=NULL,*hitPaths=NULL;

	struct pangu_http_ctx * ctx = (struct pangu_http_ctx *) pme;

	attributeObj=query_obj->attributes;
	cJSON_AddItemToArray(attributes, attributeObj);

	hitPaths=cJSON_CreateArray();
	cJSON_AddItemToObject(attributeObj, "hitPaths", hitPaths);

	cJSON *histObj=NULL;
	for(i=0; i< ctx->n_read; i++)
	{
		for(j=0; j<=query_obj->nth_scan_num; j++)
		{
			if (query_obj->nth_scan[j] == ctx->hit_path[i].Nth_scan)
			{
				if(http_hit_policy_match(result_hit_nth, k, ctx->hit_path[i].compile_id))
				{
					continue;
				}

				histObj=cJSON_CreateObject();
				cJSON_AddItemToArray(hitPaths, histObj);
				cJSON_AddNumberToObject(histObj, "itemId", ctx->hit_path[i].region_id);
				cJSON_AddNumberToObject(histObj, "objectId", ctx->hit_path[i].sub_group_id);
				if (ctx->hit_path[i].top_group_id < 0)
				{
					ctx->hit_path[i].top_group_id = ctx->hit_path[i].sub_group_id;
				}
				cJSON_AddNumberToObject(histObj, "topObjectId", ctx->hit_path[i].top_group_id);
				if(ctx->hit_path[i].compile_id > 0)
				{
					result_hit_nth[k] = ctx->hit_path[i].compile_id;
					k++;
					cJSON_AddNumberToObject(histObj, "policyId", ctx->hit_path[i].compile_id);
				}
			}
		}

	}
	http_get_location_status(attributes, attributeObj, &ctx->ip_ctx);
	http_get_fqdn_cat_id(query_obj, type, attributeObj);
}

int http_hit_policy_list(enum verify_policy_type policy_type, size_t hit_cnt, cJSON *data_obj, void *pme)
{
	bool succeeded = false;
	size_t rules=0, i=0;
	int result_config[MAX_SCAN_RESULT] = {0};

	struct pangu_http_ctx * ctx = (struct pangu_http_ctx *) pme;

	hit_cnt = ctx->hit_cnt;
	if (hit_cnt <= 0)
	{
		return 0;
	}

	if (hit_cnt >= MAX_SCAN_RESULT)	hit_cnt = MAX_SCAN_RESULT;

	ctx->action = decide_ctrl_action(policy_type, ctx->result, hit_cnt, &ctx->enforce_rules, &ctx->n_enforce);
	ctx->hit_cnt = hit_cnt;
	cJSON  *hit_obj=NULL, *policy_obj=NULL;
	hit_obj=cJSON_CreateArray();
	cJSON_AddItemToObject(data_obj, "hitPolicyList", hit_obj);
	if (ctx->hit_cnt >= 1)
	{
		for (i = 0; i < ctx->hit_cnt; i++)
		{
			if(http_hit_policy_match(result_config, i, ctx->result[i].config_id))
			{
				continue;
			}
			succeeded = false;
			policy_obj=cJSON_CreateObject();
			cJSON_AddNumberToObject(policy_obj, "policyId",ctx->result[i].config_id);
			cJSON_AddStringToObject(policy_obj, "policyName", "");

			for (rules = 0; rules < ctx->n_enforce; rules++)
			{
				if (ctx->enforce_rules[rules].config_id == ctx->result[i].config_id)
				{
					cJSON_AddBoolToObject(policy_obj, "isExecutePolicy", true);
					succeeded = true;
				}
			}
			if (succeeded == false)
			{
				cJSON_AddBoolToObject(policy_obj, "isExecutePolicy", false);
			}
			cJSON_AddItemToArray(hit_obj, policy_obj);
			result_config[i] = ctx->result[i].config_id;
		}
	}
	return 0;
}

int verify_ip_addr_to_address(struct ipaddr *ip_addr, struct ip_address *dest_ip, struct ip_address *source_ip)
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

int http_ip_location_scan(struct Maat_rule_t *result, struct ip_address *sip, struct ip_address *dip, int hit_cnt, unsigned int thread_id, enum verify_policy_type policy_type, struct pangu_http_ctx * ctx )
{
	int scan_ret=0, hit_cnt_ip=0;
	char buff[VERIFY_ARRAY_MAX]={0};
	struct Maat_hit_path_t hit_path[2048];
	struct ip_data_table* ip_location_client=NULL, *ip_location_server=NULL;

	Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY], g_pangu_rt->plolicy_table_id[POLICY_LOCATION_USER_DEFINED], sip, (void **)&ip_location_client, 1);
	Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY], g_pangu_rt->plolicy_table_id[POLICY_LOCATION_USER_DEFINED], dip, (void **)&ip_location_server, 1);

	if (ip_location_client == NULL)
	{
		Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY],  g_pangu_rt->plolicy_table_id[POLICY_LOCATION_BUILT_IN], sip, (void **)&ip_location_client, 1);
	}
	if (ip_location_server == NULL)
	{
		Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY],  g_pangu_rt->plolicy_table_id[POLICY_LOCATION_BUILT_IN], dip, (void **)&ip_location_server, 1);
	}

	int ip_location_table = 0;
	if(ip_location_server!=NULL)
	{
		memset(buff,0,sizeof(buff));
		snprintf(buff, sizeof(buff), "%s,%s,%s", ip_location_server->city_full, ip_location_server->province_full, ip_location_server->country_full);
		ctx->ip_ctx.location_server=strdup(buff);

		ip_location_table = (policy_type == PXY_TABLE_SECURITY) ? (int)PXY_SECURITY_IP_DST_LOCATION : (int)PXY_CTRL_IP_DST_LOCATION;
		memset(buff,0,sizeof(buff));
		snprintf(buff, sizeof(buff), "%s.%s.", ip_location_server->country_full, ip_location_server->city_full);
		scan_ret = Maat_full_scan_string(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][ip_location_table],
										 CHARSET_GBK, buff, strlen(buff),
										 result+hit_cnt+hit_cnt_ip, NULL, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
										 &(ctx->scan_mid), (int) thread_id);
		if(scan_ret>0)
		{
			hit_cnt_ip+=scan_ret;
		}
		ctx->n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	}
	if(ip_location_client!=NULL)
	{
		memset(buff,0,sizeof(buff));
		snprintf(buff, sizeof(buff), "%s,%s,%s", ip_location_client->city_full, ip_location_client->province_full, ip_location_client->country_full);
		ctx->ip_ctx.location_client=strdup(buff);

		ip_location_table = (policy_type == PXY_TABLE_SECURITY) ? (int)PXY_SECURITY_IP_SRC_LOCATION : (int)PXY_CTRL_IP_SRC_LOCATION;

		memset(buff,0,sizeof(buff));
		snprintf(buff, sizeof(buff), "%s.%s.", ip_location_client->country_full, ip_location_client->city_full);
		scan_ret = Maat_full_scan_string(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][ip_location_table],
										 CHARSET_GBK, buff, strlen(buff),
										 result+hit_cnt+hit_cnt_ip, NULL, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
										 &(ctx->scan_mid), (int) thread_id);
		if(scan_ret>0)
		{
			hit_cnt_ip+=scan_ret;
		}
		ctx->n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	}

	if(ip_location_server)
		ip_table_free(ip_location_server);
	if(ip_location_client)
		ip_table_free(ip_location_client);
	return hit_cnt_ip;
}

int http_ip_asn_scan(struct Maat_rule_t *result, struct ip_address* sip, struct ip_address* dip, int hit_cnt, unsigned int thread_id, enum verify_policy_type policy_type, struct pangu_http_ctx * ctx)
{
	int scan_ret=0, hit_cnt_ip=0;
	struct Maat_hit_path_t hit_path[2048];
	struct ip_data_table* ip_asn_client=NULL, *ip_asn_server=NULL;

	Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY], g_pangu_rt->plolicy_table_id[POLICY_ASN_USER_DEFINED], sip, (void **)&ip_asn_client, 1);
	Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY],  g_pangu_rt->plolicy_table_id[POLICY_ASN_USER_DEFINED], dip, (void **)&ip_asn_server, 1);

	if (ip_asn_client == NULL)
	{
		Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY],  g_pangu_rt->plolicy_table_id[POLICY_ASN_BUILT_IN], sip, (void **)&ip_asn_client, 1);
	}
	if (ip_asn_server == NULL)
	{
		Maat_ip_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY],  g_pangu_rt->plolicy_table_id[POLICY_ASN_BUILT_IN], dip, (void **)&ip_asn_server, 1);
	}

	int ip_asn_table = 0;
	if(ip_asn_server!=NULL)
	{
		ctx->ip_ctx.asn_server=strdup(ip_asn_server->asn);
		ctx->ip_ctx.organization_server=strdup(ip_asn_server->organization);

		ip_asn_table = (policy_type == PXY_TABLE_SECURITY) ? (int)PXY_SECURITY_IP_DST_ASN : (int)PXY_CTRL_IP_DST_ASN;
		scan_ret = Maat_full_scan_string(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][ip_asn_table],
										 CHARSET_UTF8, ip_asn_server->asn, strlen(ip_asn_server->asn),
										 result+hit_cnt+hit_cnt_ip, NULL, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
										 &(ctx->scan_mid), (int) thread_id);

		if(scan_ret>0)
		{
			hit_cnt_ip+=scan_ret;
		}
		ctx->n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	}
	if(ip_asn_client!=NULL)
	{
		ctx->ip_ctx.asn_client=strdup(ip_asn_client->asn);
		ctx->ip_ctx.organization_client=strdup(ip_asn_client->organization);

		ip_asn_table = (policy_type == PXY_TABLE_SECURITY) ? (int)PXY_SECURITY_IP_SRC_ASN : (int)PXY_CTRL_IP_SRC_ASN;
		scan_ret = Maat_full_scan_string(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][ip_asn_table],
										 CHARSET_UTF8, ip_asn_client->asn, strlen(ip_asn_client->asn),
										 result+hit_cnt+hit_cnt_ip, NULL, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
										 &(ctx->scan_mid), (int) thread_id);
		if(scan_ret>0)
		{
			hit_cnt_ip+=scan_ret;
		}
		ctx->n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	}
	if(ip_asn_server)
		ip_table_free(ip_asn_server);
	if(ip_asn_client)
		ip_table_free(ip_asn_client);
	return hit_cnt_ip;
}

int verify_get_fqdn_category_id(struct Maat_rule_t *result, const char *fqdn, int protocol_field, int hit_cnt, unsigned int thread_id, enum verify_policy_type policy_type,
								struct pangu_http_ctx * ctx, struct verify_policy_query_obj *query_obj)
{
	int n_read=0, hit_path_cnt=0;
	int i=0,ret=0, hit_cnt_fqdn=0;
	struct fqdn_category_t *fqdn_cat_user[8]={0},*fqdn_cat_built[8]={0};

	ret=Maat_fqdn_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY], g_pangu_rt->plolicy_table_id[POLICY_FQDN_CAT_USER_DEFINED], fqdn, (void **)fqdn_cat_user, 8);
	for(i=0; i <ret; i++)
	{
		if(i < 8)
		{
			query_obj->category_id_user[i] = fqdn_cat_user[i]->category_id;
		}
		fqdn_cat_table_free(fqdn_cat_user[i]);
	}
	query_obj->category_user_num = i< 8 ? i : 8;

	ret=Maat_fqdn_plugin_get_EX_data(g_pangu_rt->maat[PXY_TABLE_SECURITY], g_pangu_rt->plolicy_table_id[POLICY_FQDN_CAT_BUILT_IN], fqdn, (void **)fqdn_cat_built, 8);
	for(i=0; i <ret; i++)
	{
		if(i < 8)
		{
			query_obj->category_id_built[i] = fqdn_cat_built[i]->category_id;
		}
		fqdn_cat_table_free(fqdn_cat_built[i]);
	}
	query_obj->category_built_num = i< 8 ? i : 8;

	if(query_obj->category_user_num > 0)
	{
		for(i=0; i<query_obj->category_user_num; i++)
		{
			ret=Maat_scan_intval(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][protocol_field], query_obj->category_id_user[i],
							result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &(ctx->scan_mid),(int) thread_id);
			if(ret>0)
			{
				hit_cnt_fqdn+=ret;
			}
			n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, ctx->hit_path, sizeof(ctx->hit_path));
			if(ret == -2 || ret >0)
			{
				query_obj->nth_scan[hit_path_cnt] = ctx->hit_path[ctx->n_read].Nth_scan;
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
		goto finish;
	}
	if (query_obj->category_built_num > 0)
	{
		for(i=0; i<query_obj->category_built_num; i++)
		{
			ret=Maat_scan_intval(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][protocol_field], query_obj->category_id_built[i],
							result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &(ctx->scan_mid),(int) thread_id);
			if(ret>0)
			{
				hit_cnt_fqdn+=ret;
			}
			n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, ctx->hit_path, sizeof(ctx->hit_path));
			if(ret == -2 || ret >0)
			{
				query_obj->nth_scan[hit_path_cnt] = ctx->hit_path[ctx->n_read].Nth_scan;
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
	}
finish:
	query_obj->nth_scan_num = hit_path_cnt;
	return hit_cnt_fqdn;
}

size_t verify_policy_scan(enum verify_policy_type policy_type, struct verify_policy_query_obj *query_obj, cJSON *data_obj, void *pme)
{
	int scan_ret=0, n_read;

	struct pangu_http_ctx * ctx = (struct pangu_http_ctx *) pme;
	size_t hit_cnt = ctx->hit_cnt;

	int protocol_field = query_obj->protocol_field;
	const char *value = query_obj->keyword;

	if ((protocol_field == PXY_COMMON_SOURCE_ADDR || protocol_field == PXY_COMMON_DESTINATION_ADDR) && query_obj->ip_addr != NULL)
	{
		struct ip_address dest_ip, source_ip;
		verify_ip_addr_to_address(query_obj->ip_addr, &dest_ip, &source_ip);
		scan_ret = http_ip_location_scan(ctx->result, &source_ip, &dest_ip, hit_cnt, ctx->thread_id, policy_type, ctx);
		if(scan_ret > 0)
		{
			hit_cnt+=scan_ret;
		}
		scan_ret = http_ip_asn_scan(ctx->result, &source_ip, &dest_ip, hit_cnt, ctx->thread_id, policy_type, ctx);
		if(scan_ret > 0)
		{
			hit_cnt+=scan_ret;
		}

		scan_ret = Maat_scan_proto_addr(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][protocol_field], query_obj->ip_addr, 0,
				   ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt, &(ctx->scan_mid), ctx->thread_id);
		if (scan_ret > 0)
		{
			hit_cnt += scan_ret;
		}
		n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, ctx->hit_path, sizeof(ctx->hit_path));
		query_obj->nth_scan[0] = ctx->hit_path[ctx->n_read].Nth_scan;
		ctx->n_read=n_read;
		goto decide;
	}

	if (protocol_field == PXY_CTRL_APP_ID)
	{
		int scan_val=atoi(value);
		scan_ret=Maat_scan_intval(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][protocol_field], scan_val, ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt, &(ctx->scan_mid), ctx->thread_id);
		if(scan_ret>0)
		{
			hit_cnt+=scan_ret;
		}
		n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, ctx->hit_path, sizeof(ctx->hit_path));
		query_obj->nth_scan[0] = ctx->hit_path[ctx->n_read].Nth_scan;
		ctx->n_read=n_read;
		goto decide;
	}

	if ((protocol_field == PXY_CTRL_HTTP_REQ_HDR) || protocol_field == PXY_CTRL_HTTP_RES_HDR)
	{
		if(query_obj->district != NULL)
		{
			const char * str_field_name = query_obj->district;
			scan_ret = Maat_set_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_SET_SCAN_DISTRICT,
					   str_field_name, strlen(str_field_name));
			assert(scan_ret == 0);
			scan_ret = Maat_full_scan_string(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][protocol_field],
				CHARSET_UTF8, value, strlen(value),
				ctx->result + hit_cnt, NULL, MAX_SCAN_RESULT - hit_cnt, &(ctx->scan_mid), ctx->thread_id);
			if (scan_ret > 0)
			{
				hit_cnt += scan_ret;
			}
			n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, ctx->hit_path, sizeof(ctx->hit_path));
			query_obj->nth_scan[0] = ctx->hit_path[ctx->n_read].Nth_scan;
			ctx->n_read=n_read;
		}
	}

	if(policy_type == PXY_TABLE_SECURITY &&(protocol_field == PXY_SECURITY_HTTP_FQDN ||
	   protocol_field == PXY_SECURITY_HTTPS_SNI || protocol_field==PXY_SECURITY_HTTPS_CN || protocol_field==PXY_SECURITY_HTTPS_SAN ||
       protocol_field==PXY_SECURITY_DNS_QNAME || protocol_field == PXY_SECURITY_QUIC_SNI))
	{
		scan_ret = verify_get_fqdn_category_id(ctx->result, value, protocol_field, hit_cnt, ctx->thread_id, policy_type, ctx, query_obj);
		if(scan_ret>0)
		{
			hit_cnt+=scan_ret;
		}
	}

	if(policy_type == PXY_TABLE_MANIPULATION &&(protocol_field == PXY_CTRL_HTTP_FQDN ||
			protocol_field == PXY_CTRL_DOH_QNAME || protocol_field==PXY_CTRL_DOH_HOST))
	{
		scan_ret = verify_get_fqdn_category_id(ctx->result, value, protocol_field, hit_cnt, ctx->thread_id, policy_type, ctx, query_obj);
		if(scan_ret>0)
		{
			hit_cnt+=scan_ret;
		}
	}
	scan_ret = Maat_full_scan_string(g_pangu_rt->maat[policy_type], g_pangu_rt->scan_table_id[policy_type][protocol_field],
									CHARSET_UTF8, value, strlen(value),
									ctx->result+hit_cnt, NULL, MAX_SCAN_RESULT-hit_cnt,
									&(ctx->scan_mid), ctx->thread_id);
	if(scan_ret>0)
	{
		hit_cnt+=scan_ret;
	}
	n_read=Maat_get_scan_status(g_pangu_rt->maat[policy_type], &(ctx->scan_mid), MAAT_GET_SCAN_HIT_PATH, ctx->hit_path, sizeof(ctx->hit_path));
	if(scan_ret == -2 || scan_ret >0)
	{
		query_obj->nth_scan[0] = ctx->hit_path[ctx->n_read].Nth_scan;
		ctx->n_read=n_read;
	}
decide:
	ctx->hit_cnt = hit_cnt;
	//http_hit_policy_list(g_pangu_rt->maat[policy_type], hit_cnt, data_obj, (void *)ctx);
	return hit_cnt;
}

static Maat_feather_t create_maat_feather(const char * instance_name, const char * profile, const char * section, const char *table_name, int max_thread, void * logger)
{
	Maat_feather_t target;
	int input_mode = 0, maat_perf_on = 0;
	int ret = 0, scan_detail = 0, effect_interval = 60;
	char table_info[VERIFY_STRING_MAX] = {0}, inc_cfg_dir[VERIFY_STRING_MAX] = {0}, ful_cfg_dir[VERIFY_STRING_MAX] = {0};
	char redis_server[VERIFY_STRING_MAX] = {0};
	char redis_port_range[VERIFY_STRING_MAX] = {0};
	char accept_tags[VERIFY_STRING_MAX] = {0};
	int redis_port_begin=0, redis_port_end=0;
	int redis_port_select=0;
	int redis_db_idx = 0;
	char json_cfg_file[VERIFY_STRING_MAX] = {0};
	MESA_load_profile_int_def(profile, section, "maat_input_mode", &(input_mode), 0);
	MESA_load_profile_int_def(profile, section, "perf_switch", &(maat_perf_on), 1);

	MESA_load_profile_string_def(profile, section, table_name, table_info, sizeof(table_info), "");
	MESA_load_profile_string_def(profile, section, "accept_tags", accept_tags, sizeof(accept_tags), "");

	MESA_load_profile_string_def(profile, section, "json_cfg_file", json_cfg_file, sizeof(json_cfg_file), "");

	MESA_load_profile_string_def(profile, section, "maat_redis_server", redis_server, sizeof(redis_server), "");
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "%s:%s", "Maat Redis Ip", redis_server);
	MESA_load_profile_string_def(profile, section, "maat_redis_port_range", redis_port_range, sizeof(redis_server), "6379");
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "%s:%s", "Maat Redis Port", redis_port_range);
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
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Invalid redis port range %s, MAAT init failed.", redis_port_range);
	}
	MESA_load_profile_int_def(profile, section, "maat_redis_db_index", &(redis_db_idx), 0);

	MESA_load_profile_string_def(profile, section, "inc_cfg_dir", inc_cfg_dir, sizeof(inc_cfg_dir), "");
	MESA_load_profile_string_def(profile, section, "full_cfg_dir", ful_cfg_dir, sizeof(ful_cfg_dir), "");
	MESA_load_profile_int_def(profile, section, "effect_interval_s", &(effect_interval), 60);

	effect_interval *= 1000;//convert s to ms
	assert(strlen(inc_cfg_dir) != 0 || strlen(ful_cfg_dir) != 0 || strlen(redis_server)!=0 || strlen(json_cfg_file)!=0);

	target = Maat_feather(max_thread, table_info, logger);
	Maat_set_feather_opt(target, MAAT_OPT_INSTANCE_NAME, instance_name, strlen(instance_name) + 1);
	switch (input_mode)
	{
		case MAAT_INPUT_JSON:
			Maat_set_feather_opt(target, MAAT_OPT_JSON_FILE_PATH, json_cfg_file, strlen(json_cfg_file) + 1);
			break;
		case MAAT_INPUT_REDIS:
			Maat_set_feather_opt(target, MAAT_OPT_REDIS_IP, redis_server, strlen(redis_server) + 1);
			Maat_set_feather_opt(target, MAAT_OPT_REDIS_PORT, &redis_port_select, sizeof(redis_port_select));
			Maat_set_feather_opt(target, MAAT_OPT_REDIS_INDEX, &redis_db_idx, sizeof(redis_db_idx));
			break;
		case MAAT_INPUT_FILE: Maat_set_feather_opt(target, MAAT_OPT_FULL_CFG_DIR, ful_cfg_dir, strlen(ful_cfg_dir) + 1);
			Maat_set_feather_opt(target, MAAT_OPT_INC_CFG_DIR, inc_cfg_dir, strlen(inc_cfg_dir) + 1);
			break;
		default: mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Invalid MAAT Input Mode: %d.", input_mode);
			goto error_out;
			break;
	}

	Maat_set_feather_opt(target, MAAT_OPT_FOREIGN_CONT_DIR, "./pangu_files", strlen("./pangu_files")+1);

	Maat_set_feather_opt(target, MAAT_OPT_EFFECT_INVERVAL_MS, &effect_interval, sizeof(effect_interval));
	Maat_set_feather_opt(target, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));

	ret = Maat_initiate_feather(target);
	if (ret < 0)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s MAAT init failed.", __FUNCTION__);
		goto error_out;
	}

	return target;
error_out:
	Maat_burn_feather(target);
	return NULL;
}

static int get_column_pos(const char* line, int column_seq, size_t *offset, size_t *len)
{
	const char* seps=" \t";
	char* saveptr=NULL, *subtoken=NULL, *str=NULL;
	char* dup_line=strdup(line);
	int i=0, ret=-1;
	for (str = dup_line; ; str = NULL)
	{
		subtoken = strtok_r(str, seps, &saveptr);
		if (subtoken == NULL)
			break;
		if(i==column_seq-1)
		{
			*offset=subtoken-dup_line;
			*len=strlen(subtoken);
			ret=0;
			break;
		}
		i++;
	}
	free(dup_line);
	return ret;
}

void subscribe_id_new_cb(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int ret=0;
	size_t subscribe_id_offset, len;
	ret=get_column_pos(table_line, 4, &subscribe_id_offset, &len);
	if(ret<0)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Add subscribe ID faild: %s", table_line);
		return;
	}
	*ad=ALLOC(char, len+1);
	memcpy(*ad, table_line+subscribe_id_offset, len);
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Add subscribe ID: %s", (char*)*ad);
	return;
}

void subscribe_id_free_cb(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Delete subscribe ID: %s", (char*)*ad);
	free(*ad);
	*ad=NULL;
}

void subscribe_id_dup_cb(int table_id, MAAT_PLUGIN_EX_DATA* to, MAAT_PLUGIN_EX_DATA* from, long argl, void* argp)
{
	*to = strdup((char*)*from);
	return;
}

int wannat_policy_init(struct verify_policy * verify, const char* profile_path)
{
	int ret = -1;

	g_pangu_rt->maat[PXY_TABLE_WANNAT] = create_maat_feather("static", profile_path, "MAAT", "table_info_wannat", g_pangu_rt->thread_num, g_pangu_rt->local_logger);
	if (!g_pangu_rt->maat[PXY_TABLE_WANNAT])
	{
		goto error_out;
	}
	const char * table_name[__WANNAT_TABLE_MAX];
	table_name[PXY_WANNAT_SOURCE_ADDR] = "TSG_SECURITY_SOURCE_ADDR";
	table_name[PXY_WANNAT_DESTINATION_ADDR] = "TSG_SECURITY_DESTINATION_ADDR";

	for (int i = 0; i < __WANNAT_TABLE_MAX; i++)
	{
		g_pangu_rt->scan_table_id[PXY_TABLE_WANNAT][i] = Maat_table_register(g_pangu_rt->maat[PXY_TABLE_WANNAT], table_name[i]);
		if (g_pangu_rt->scan_table_id[PXY_TABLE_WANNAT][i] < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Wannat policy maat table %s register failed.", table_name[i]);
			goto error_out;
		}
		mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Wannat policy register maat %p, table name %s, table id %d", g_pangu_rt->maat[PXY_TABLE_WANNAT], table_name[i], g_pangu_rt->scan_table_id[PXY_TABLE_WANNAT][i]);
	}
	ret = 0;
error_out:
	return ret;
}

int proxy_policy_init(struct verify_policy * verify, const char* profile_path)
{
	int ret = -1;

	g_pangu_rt = ALLOC(struct pangu_rt, 1);

	g_pangu_rt->thread_num = verify->nr_work_threads;
	g_pangu_rt->local_logger = verify->logger;
	g_pangu_rt->maat[PXY_TABLE_MANIPULATION] = create_maat_feather("static", profile_path, "MAAT", "table_info", g_pangu_rt->thread_num, g_pangu_rt->local_logger);
	if (!g_pangu_rt->maat[PXY_TABLE_MANIPULATION])
	{
		goto error_out;
	}

	const char * table_name[__SCAN_TABLE_MAX];
	table_name[PXY_CTRL_SOURCE_ADDR] = "TSG_SECURITY_SOURCE_ADDR";
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
	table_name[PXY_CTRL_IP_SRC_ASN]="TSG_SECURITY_SOURCE_ASN";
	table_name[PXY_CTRL_IP_DST_ASN]="TSG_SECURITY_DESTINATION_ASN";
	table_name[PXY_CTRL_IP_SRC_LOCATION]="TSG_SECURITY_SOURCE_LOCATION";
	table_name[PXY_CTRL_IP_DST_LOCATION]="TSG_SECURITY_DESTINATION_LOCATION";
	table_name[PXY_CTRL_IMSI]="TSG_FILED_GTP_IMSI";
	table_name[PXY_CTRL_PHONE_NUMBER]="TSG_FILED_GTP_PHONE_NUMBER";
	table_name[PXY_CTRL_APN]="TSG_FILED_GTP_APN";
	for (int i = 0; i < __SCAN_TABLE_MAX; i++)
	{
		g_pangu_rt->scan_table_id[PXY_TABLE_MANIPULATION][i] = Maat_table_register(g_pangu_rt->maat[PXY_TABLE_MANIPULATION], table_name[i]);
		if (g_pangu_rt->scan_table_id[PXY_TABLE_MANIPULATION][i] < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Pangu HTTP Maat table %s register failed.", table_name[i]);
			goto error_out;
		}
		mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Pangu policy register maat %p, table name %s, table id %d", g_pangu_rt->maat[PXY_TABLE_MANIPULATION], table_name[i], g_pangu_rt->scan_table_id[PXY_TABLE_MANIPULATION][i]);
	}
	g_pangu_rt->dyn_maat = create_maat_feather("dyn", profile_path, "DYNAMIC_MAAT", "table_info", g_pangu_rt->thread_num, g_pangu_rt->local_logger);
	if (!g_pangu_rt->dyn_maat)
	{
		goto error_out;
	}
	g_pangu_rt->subscriber_id_table_id=Maat_table_register(g_pangu_rt->dyn_maat, "TSG_DYN_SUBSCRIBER_IP");
	ret=Maat_plugin_EX_register(g_pangu_rt->dyn_maat,
							g_pangu_rt->subscriber_id_table_id,
							subscribe_id_new_cb,
							subscribe_id_free_cb,
							subscribe_id_dup_cb,
							NULL,
							0,
							NULL);
	if(ret!=0)
	{
		mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Pangu HTTP Dynamic Maat  TSG_DYN_SUBSCRIBER_IP EX data register failed.");
		goto error_out;
	}
	ret = 0;
error_out:
	return ret;
}

int security_policy_init(struct verify_policy * verify, const char* profile_path)
{
	int ret = -1;

	g_pangu_rt->maat[PXY_TABLE_SECURITY] = create_maat_feather("static", profile_path, "MAAT", "table_info_tsg", g_pangu_rt->thread_num, g_pangu_rt->local_logger);
	if (!g_pangu_rt->maat[PXY_TABLE_SECURITY])
	{
		goto error_out;
	}
	const char * table_name[__SECURITY_TABLE_MAX];
	table_name[PXY_SECURITY_SOURCE_ADDR] = "TSG_SECURITY_SOURCE_ADDR";
	table_name[PXY_SECURITY_DESTINATION_ADDR] = "TSG_SECURITY_DESTINATION_ADDR";
	table_name[PXY_SECURITY_HTTP_URL] = "TSG_FIELD_HTTP_URL";
	table_name[PXY_SECURITY_HTTP_FQDN] = "TSG_FIELD_HTTP_HOST";
	table_name[PXY_SECURITY_HTTP_REQ_HDR] = "TSG_FIELD_HTTP_REQ_HDR";
	table_name[PXY_SECURITY_HTTP_REQ_BODY] = "TSG_FIELD_HTTP_REQ_BODY";
	table_name[PXY_SECURITY_HTTP_RES_HDR] = "TSG_FIELD_HTTP_RES_HDR";
	table_name[PXY_SECURITY_HTTP_RES_BODY] = "TSG_FIELD_HTTP_RES_BODY";
	table_name[PXY_SECURITY_SUBSCRIBE_ID] = "TSG_OBJ_SUBSCRIBER_ID";
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
	table_name[PXY_SECURITY_APP_ID] = "TSG_OBJ_APP_ID";
	table_name[PXY_SECURITY_IP_SRC_ASN]="TSG_SECURITY_SOURCE_ASN";
	table_name[PXY_SECURITY_IP_DST_ASN]="TSG_SECURITY_DESTINATION_ASN";
	table_name[PXY_SECURITY_IP_SRC_LOCATION]="TSG_SECURITY_SOURCE_LOCATION";
	table_name[PXY_SECURITY_IP_DST_LOCATION]="TSG_SECURITY_DESTINATION_LOCATION";
	table_name[PXY_SECURITY_SIP_FROM]="TSG_FIELD_SIP_ORIGINATOR_DESCRIPTION";
	table_name[PXY_SECURITY_SIP_TO]="TSG_FIELD_SIP_RESPONDER_DESCRIPTION";
	table_name[PXY_SECURITY_IMSI]="TSG_FILED_GTP_IMSI";
	table_name[PXY_SECURITY_PHONE_NUMBER]="TSG_FILED_GTP_PHONE_NUMBER";
	table_name[PXY_SECURITY_APN]="TSG_FILED_GTP_APN";

	for (int i = 0; i < __SECURITY_TABLE_MAX; i++)
	{
		g_pangu_rt->scan_table_id[PXY_TABLE_SECURITY][i] = Maat_table_register(g_pangu_rt->maat[PXY_TABLE_SECURITY], table_name[i]);
		if (g_pangu_rt->scan_table_id[PXY_TABLE_SECURITY][i] < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Security policy maat table %s register failed.", table_name[i]);
			goto error_out;
		}
		mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Security policy register maat %p, table name %s, table id %d", g_pangu_rt->maat[PXY_TABLE_SECURITY], table_name[i], g_pangu_rt->scan_table_id[PXY_TABLE_SECURITY][i]);
	}

	for(int i = POLICY_ASN_USER_DEFINED; i < POLICY_FQDN_CAT_USER_DEFINED; i++)
	{
		ret = maat_ip_table_init(i, ip_table_free_cb, ip_table_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}
	}

	for(int i = POLICY_FQDN_CAT_USER_DEFINED; i < POLICY_PROFILE_TABLE_MAX; i++)
	{
		ret = maat_fqdn_cat_table_init(i, fqdn_cat_new_data, fqdn_cat_free_data, fqdn_cat_dup_data);
		if(ret<0)
		{
			goto error_out;
		}
	}

	ret = 0;
error_out:
	return ret;
}

