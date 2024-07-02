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

#include <MESA/maat.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/stream.h>

#include <cjson/cJSON.h>

#include "verify_policy.h"
#include "verify_policy_utils.h"

#define HIT_PATH_SIZE           	4096
#define	MAX_SCAN_RESULT				16

#define	MODULE_VERIFY_MATCHER "verify-policy.matcher"

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
	PROFILE_ASN_USER_DEFINED,
	PROFILE_ASN_BUILT_IN,
	PROFILE_LOCATION_USER_DEFINED,
	PROFILE_LOCATION_BUILT_IN,
	PROFILE_FQDN_CAT_USER_DEFINED,
	PROFILE_FQDN_CAT_BUILT_IN,
	PROFILE_TUNNEL_CATALOG,
	PROFILE_TUNNEL_ENDPOINT,
	PROFILE_TUNNEL_LABEL,
	PROFILE_APP_DI_DICT,
	PROFILE_TABLE_MAX,
};

struct ip_data_table
{
	int profile_id;
	int asn_group_id;
	int geoname_group_id;
	int country_region_group_id;
	int province_group_id;
	int city_group_id;
	int subdivision_group_id;
	char *asn;
	char *organization;
	char *country_full;
	char *province_full;
	char *city_full;
	char *subdivision_addr;
	int ref_cnt;
	pthread_mutex_t lock;
};

struct http_field_name
{
	const char * field_name;
	enum http_std_field field_id;
};

enum nth_scan_type
{
	NTH_SCAN_IP_SRC_GEO_COUNTRY = 0,
	NTH_SCAN_IP_SRC_GEO_SUPER_ADMINISTRATIVE_AREA,
	NTH_SCAN_IP_SRC_GEO_ADMINISTRATIVE_AREA,
	NTH_SCAN_IP_SRC_GEO_SUB_ADMINISTRATIVE_AREA,
	NTH_SCAN_IP_DST_GEO_COUNTRY,
	NTH_SCAN_IP_DST_GEO_SUPER_ADMINISTRATIVE_AREA,
	NTH_SCAN_IP_DST_GEO_ADMINISTRATIVE_AREA,
	NTH_SCAN_IP_DST_GEO_SUB_ADMINISTRATIVE_AREA,
	NTH_SCAN_IP_DST_ASN,
	NTH_SCAN_IP_SRC_ASN,
	NTH_SCAN_IP_INTERNAL_ASN,
	NTH_SCAN_IP_EXTERNAL_ASN,
	NTH_SCAN_MAX
};

/** Nth_scan: Since there is no virtual table name in the request due to IP location and IP protocol,
 * the current hit path scan count needs to be recorded to correspond to the virtual table name */
struct ip_data_ctx
{
	char *asn_client;
	char *asn_server;
	char *organization_client;
	char *organization_server;
	char *location_client;
	char *location_server;
	int Nth_scan[NTH_SCAN_MAX];
};

struct fqdn_category_ctx
{
	int ref_cnt;
	unsigned int fqdn_cat_id;
	int match_method;
	char fqdn[VERIFY_ARRAY_MAX];

	long long int group_id;
	pthread_mutex_t lock;
};

struct tunnel_data_ctx
{
	int id;
	int ref_cnt;
	char *name;
	char *type;
	char *composition;
	char *description;

	long long int group_id;
	pthread_mutex_t lock;
};

struct rule_data_ctx
{
	int     ref_cnt;
	int		config_id;
	int		service_id;
	unsigned char	action;
	pthread_mutex_t lock;
};

struct app_id_dict
{
	int ref_cnt;
	int app_id;
	long long int group_id;

	pthread_mutex_t lock;
};

struct policy_scan_ctx
{
	int thread_id;
	enum policy_action action;
	char * action_para;
	struct maat_state *scan_mid;
	size_t hit_cnt;
	long long result[MAX_SCAN_RESULT];
	struct rule_data_ctx *hit_rules;

	size_t n_enforce;
	struct rule_data_ctx * enforce_rules;
	int n_read;
	struct maat_hit_path hit_path[HIT_PATH_SIZE];

	int ip_protocol_num;
	int tunnel_endpoint_x;
	int bool_id_array_idx;
    unsigned long long bool_id_array[256];
	
	struct ip_data_ctx ip_ctx;
	
	/*exception handling*/
	int tunnel_scan;
	long long tunnel_result[2];
	struct maat_state *tunnel_scan_mid;
};

struct verify_policy_rt
{
	struct maat *feather[VSYS_ID_MAX];
	struct log_handle *local_logger;
	int log_level;
	int thread_num;
	int load_ip_location;
	int load_fqdn_cat;
	int hit_path_size;
	int compile_table_id[__SCAN_POLICY_MAX];
	int plugin_table_id[__SCAN_POLICY_MAX];
	int profile_table_id  [PROFILE_TABLE_MAX];
	int scan_table_id[__TSG_OBJ_MAX];
};

struct verify_policy_rt * g_policy_rt;

#define MAAT_INPUT_JSON			0
#define MAAT_INPUT_REDIS    	1
#define MAAT_INPUT_FILE        	2

#define BOOLEAN_TRUE_GROUP_ID 	2
#define BOOLEAN_FLASE_GROUP_ID	3
#define PROTOCOL_ANY_GROUP_ID 	4
#define PROTOCOL_ICMP_GROUP_ID	5
#define PROTOCOL_TCP_GROUP_ID	6
#define PROTOCOL_UDP_GROUP_ID 	7

void verify_policy_tunnle_add(void * pme)
{
	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *) pme;
	ctx->tunnel_endpoint_x++;
}

void *policy_scan_ctx_new(unsigned int thread_id, int vsys_id, int compile_table_id)
{
	struct policy_scan_ctx * ctx = ALLOC(struct policy_scan_ctx, 1);
	ctx->thread_id = thread_id;;
	ctx->scan_mid = maat_state_new(g_policy_rt->feather[vsys_id], thread_id);
	maat_state_set_scan_compile_table(ctx->scan_mid, g_policy_rt->compile_table_id[compile_table_id]);

	return (void *)ctx;
}

void policy_scan_ctx_free(void * pme)
{
	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *) pme;

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

void ip_asn_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int addr_type, group_id=0;
	int ret=0,profile_id=0,is_valid=0;
	char addr_format[40]={0};
	char start_ip[40], end_ip[40],asn[40]={0};
	char organization[VERIFY_ARRAY_MAX];

	ret=sscanf(table_line, "%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%d", &profile_id, &group_id, &addr_type, addr_format, start_ip, end_ip, asn, organization, &is_valid);
	if(ret!=9)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy table parse ip ASN failed, ret:%d, %s", ret, table_line);
		return;
	}
	verify_unescape(organization);

	struct ip_data_table* ip_asn=ALLOC(struct ip_data_table, 1);
	memset(ip_asn, 0, sizeof(struct ip_data_table));
	ip_asn->profile_id=profile_id;
	ip_asn->asn=strdup(asn);
	ip_asn->organization=strdup(organization);
	ip_asn->asn_group_id=group_id;
	ip_asn->ref_cnt=1;
	pthread_mutex_init(&(ip_asn->lock), NULL);

	log_debug(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy table add success %d", profile_id);
	*ad = ip_asn;
}

void ip_location_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0,profile_id=0,is_valid=0;
	int geoname_id=0, addr_type=0;
	char addr_format[VERIFY_PATH_MAX];
	int country_region_group_id=0;
	int province_group_id=0,city_group_id=0,subdivision_group_id=0;
	double latitude, longitude, coords;
	char language[40], start_ip[40], end_ip[40];
	char continent_abbr[VERIFY_ARRAY_MAX],continent_full[VERIFY_ARRAY_MAX];
	char country_abbr[VERIFY_ARRAY_MAX],province_abbr[VERIFY_ARRAY_MAX], time_zone[VERIFY_ARRAY_MAX];
	char country_full[VERIFY_ARRAY_MAX],province_full[VERIFY_ARRAY_MAX], city_full[VERIFY_ARRAY_MAX];
	char subdivision_addr[VERIFY_STRING_MAX];

	ret=sscanf(table_line, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t %s\t%s\t%s\t%lf\t%lf\t%lf\t%s\t %s\t%s\t%s\t%s\t%s\t%s \t%s\t%s\t%s\t%d", &profile_id,&geoname_id,
			   &country_region_group_id,&province_group_id,&city_group_id,&subdivision_group_id,&addr_type,addr_format,start_ip,end_ip,&latitude,&longitude,&coords,language,
			   continent_abbr,continent_full,country_abbr,country_full,province_abbr,province_full,city_full,subdivision_addr,time_zone,&is_valid);

	if(ret != 24)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy table parse ip location failed, ret:%d, %s", ret, table_line);
		return;
	}

	verify_unescape(continent_full);
	verify_unescape(country_full);
	verify_unescape(province_full);
	verify_unescape(city_full);
	verify_unescape(subdivision_addr);

	struct ip_data_table* ip_location=ALLOC(struct ip_data_table, 1);
	memset(ip_location, 0, sizeof(struct ip_data_table));
	ip_location->profile_id=profile_id;
	ip_location->country_region_group_id=country_region_group_id;
	ip_location->province_group_id=province_group_id;
	ip_location->city_group_id=city_group_id;
	ip_location->subdivision_group_id=subdivision_group_id;
	ip_location->country_full=strdup(country_full);
	ip_location->province_full=strdup(province_full);
	ip_location->city_full=strdup(city_full);
	ip_location->subdivision_addr=strdup(subdivision_addr);
	ip_location->ref_cnt=1;
	pthread_mutex_init(&(ip_location->lock), NULL);
	log_debug(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy table add success %d", profile_id);
	*ad = ip_location;
}

void ip_table_dup_cb(int table_id, void **to, void **from, long argl, void* argp)
{
	struct ip_data_table* ip_asn=(struct ip_data_table*)(*from);
	pthread_mutex_lock(&(ip_asn->lock));
	ip_asn->ref_cnt++;
	pthread_mutex_unlock(&(ip_asn->lock));
	*to=ip_asn;
}

void ip_table_free_cb(int table_id, void **ad, long argl, void* argp)
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
	if(ip_asn->subdivision_addr) FREE(&ip_asn->subdivision_addr);

	FREE(&ip_asn);
	*ad=NULL;
	return;
}

void ip_table_free(struct ip_data_table* ip_asn)
{
	ip_table_free_cb(0, (void **)&ip_asn, 0, NULL);
}

void tunnel_catalog_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0,tunnel_id=0,group_id=0,is_valid=0;
	char tunnel_name[VERIFY_ARRAY_MAX]={0},tunnel_type[16]={0};
	char composition[VERIFY_ARRAY_MAX]={0};

	ret=sscanf(table_line, "%d\t%s\t%s\t%s\t%d\t%d", &tunnel_id, tunnel_name, tunnel_type, composition, &group_id, &is_valid);
	if(ret!=6)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy catalog table parse tunnel catalog failed, ret:%d, %s", ret, table_line);
		return;
	}

	struct tunnel_data_ctx *tunnel=ALLOC(struct tunnel_data_ctx, 1);
	memset(tunnel, 0, sizeof(struct tunnel_data_ctx));
	tunnel->id=tunnel_id;
	tunnel->name=strdup(tunnel_name);
	tunnel->type=strdup(tunnel_type);
	tunnel->composition=strdup(composition);
	tunnel->group_id=group_id;
	tunnel->ref_cnt=1;
	pthread_mutex_init(&(tunnel->lock), NULL);

	log_debug(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy table add success %d", tunnel_id);
	*ad = tunnel;
}

void tunnel_endpoint_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0,is_valid=0;
	int endpoint_id=0,addr_type=0;
	char start_ip[40], end_ip[40];
	char description[VERIFY_ARRAY_MAX];

	ret=sscanf(table_line, "%d\t%d\t%s\t%s\t%s\t%d", &endpoint_id, &addr_type, start_ip, end_ip, description, &is_valid);
	if(ret!=6)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy table parse tunnel end point failed, ret:%d, %s", ret, table_line);
		return;
	}

	struct tunnel_data_ctx* tunnel=ALLOC(struct tunnel_data_ctx, 1);
	memset(tunnel, 0, sizeof(struct tunnel_data_ctx));
	tunnel->id=endpoint_id;
	tunnel->description=strdup(description);
	tunnel->ref_cnt=1;
	pthread_mutex_init(&(tunnel->lock), NULL);

	log_debug(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy endpoint table add success %d", endpoint_id);
	*ad = tunnel;
}

void tunnel_label_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0,is_valid=0;
	int label_id=0;

	ret=sscanf(table_line, "%d\t%d", &label_id, &is_valid);
	if(ret!=2)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy table tunnel label failed, ret:%d, %s", ret, table_line);
		return;
	}

	struct tunnel_data_ctx* tunnel=ALLOC(struct tunnel_data_ctx, 1);
	memset(tunnel, 0, sizeof(struct tunnel_data_ctx));
	tunnel->id=label_id;
	tunnel->ref_cnt=1;
	pthread_mutex_init(&(tunnel->lock), NULL);

	log_debug(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Policy label table add success %d", label_id);
	*ad = tunnel;
}


const char *table_name_map[] = {"TSG_OBJ_IP_ASN_USER_DEFINED",
								"TSG_OBJ_IP_ASN_BUILT_IN",
								"TSG_IP_LOCATION_USER_DEFINED",
								"TSG_IP_LOCATION_BUILT_IN",
								"TSG_FQDN_CATEGORY_USER_DEFINED",
								"TSG_FQDN_CATEGORY_BUILT_IN",
								"TSG_TUNNEL_CATALOG",
								"TSG_TUNNEL_ENDPOINT",
								"TSG_TUNNEL_LABEL",
								"APP_ID_DICT"};

int maat_tunnel_table_init(int profile_idx,int vsys_id,
					   	   maat_ex_free_func_t* free_func,
					       maat_ex_dup_func_t* dup_func)
{
	int table_id=0;

	maat_ex_new_func_t *new_func[] = {
			[PROFILE_ASN_USER_DEFINED] = NULL,
			[PROFILE_ASN_BUILT_IN] = NULL,
			[PROFILE_LOCATION_USER_DEFINED] = NULL,
			[PROFILE_LOCATION_BUILT_IN] = NULL,
			[PROFILE_FQDN_CAT_USER_DEFINED] = NULL,
			[PROFILE_FQDN_CAT_BUILT_IN] = NULL,
			[PROFILE_TUNNEL_CATALOG] = tunnel_catalog_table_new_cb,
			[PROFILE_TUNNEL_ENDPOINT] = tunnel_endpoint_table_new_cb,
			[PROFILE_TUNNEL_LABEL] = tunnel_label_table_new_cb
	};

	const char *table_name = table_name_map[profile_idx];
	table_id=g_policy_rt->profile_table_id[profile_idx]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id > 0)
	{
		table_id=maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, new_func[profile_idx], free_func, dup_func, 0, NULL);
		return table_id;
	}
	log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Register table %s failed.", table_name);
	return -1;
}

void tunnel_table_free_data(int table_id, void **ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}

	struct tunnel_data_ctx *tunnel=(struct tunnel_data_ctx *)(*ad);
	pthread_mutex_lock(&(tunnel->lock));
	tunnel->ref_cnt--;
	if(tunnel->ref_cnt>0)
	{
		pthread_mutex_unlock(&(tunnel->lock));
		return;
	}
	pthread_mutex_unlock(&(tunnel->lock));
	pthread_mutex_destroy(&(tunnel->lock));

	if(tunnel->name)
		FREE(&tunnel->name);
	if(tunnel->type)
		FREE(&tunnel->type);
	if(tunnel->composition)
		FREE(&tunnel->composition);
	if(tunnel->description)
		FREE(&tunnel->description);
	FREE(&tunnel);

	*ad=NULL;
	return;
}

void tunnel_table_free(struct tunnel_data_ctx* tunnel)
{
	tunnel_table_free_data(0, (void **)&tunnel, 0, NULL);
}

void tunnel_table_dup_data(int table_id, void **to, void **from, long argl, void* argp)
{
	struct tunnel_data_ctx *tunnel=(struct tunnel_data_ctx *)(*from);
	pthread_mutex_lock(&(tunnel->lock));
	tunnel->ref_cnt++;
	pthread_mutex_unlock(&(tunnel->lock));
	*to=tunnel;

	return;
}

int maat_plugin_table_ex_init(int profile_idx, int vsys_id,
							  maat_ex_new_func_t* new_func,
							  maat_ex_free_func_t* free_func,
							  maat_ex_dup_func_t* dup_func)
{
	int table_id=0, ret=0;

	const char *table_name = table_name_map[profile_idx];
	table_id=g_policy_rt->profile_table_id[profile_idx]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id >= 0)
	{
		ret=maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, new_func, free_func, dup_func, 0, NULL);
		return ret;
	}
	log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Register maat plugin table %s failed.", table_name);
	return -1;
}

void app_dict_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0;
	size_t offset=0, len=0;
	char *app_id_str=NULL, *group_id_str=NULL;
	struct app_id_dict *app_dict=ALLOC(struct app_id_dict, 1);

	ret = maat_helper_read_column(table_line, 1, &offset, &len);
	if(ret >= 0)
	{
		app_id_str=ALLOC(char, len+1);
		memcpy(app_id_str, table_line+offset, len);
		app_dict->app_id=atoi(app_id_str);
		FREE(&app_id_str);
	}
	
	ret = maat_helper_read_column(table_line, 18, &offset, &len);
	if(ret >= 0)
	{
		group_id_str=ALLOC(char, len+1);
		memcpy(group_id_str, table_line+offset, len);
		app_dict->group_id=atoll(group_id_str);
		FREE(&group_id_str);
	}

	app_dict->ref_cnt=1;
	pthread_mutex_init(&(app_dict->lock), NULL);
	*ad=app_dict;
	return;
}

void app_dict_table_free_cb(int table_id, void **ad, long argl, void* argp)
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

void app_dict_table_dup_cb(int table_id, void **to, void **from, long argl, void* argp)
{
	struct app_id_dict *app_dict=(struct app_id_dict *)(*from);
	pthread_mutex_lock(&(app_dict->lock));
	app_dict->ref_cnt++;
	pthread_mutex_unlock(&(app_dict->lock));
	*to=app_dict;

	return;
}

int maat_ip_table_init(int profile_idx,int vsys_id,
					   maat_ex_free_func_t* free_func,
					   maat_ex_dup_func_t* dup_func)
{
	int table_id=0;

	maat_ex_new_func_t *new_func[] = {
			[PROFILE_ASN_USER_DEFINED] = ip_asn_table_new_cb,
			[PROFILE_ASN_BUILT_IN] = ip_asn_table_new_cb,
			[PROFILE_LOCATION_USER_DEFINED] = ip_location_table_new_cb,
			[PROFILE_LOCATION_BUILT_IN] = ip_location_table_new_cb,
	};

	const char *table_name = table_name_map[profile_idx];
	table_id=g_policy_rt->profile_table_id[profile_idx]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id >= 0)
	{
		table_id=maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, new_func[profile_idx], free_func, dup_func,
									  				  0, NULL);
		return 0;
	}
	log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Register table %s failed.", table_name);
	return -1;
}

void fqdn_cat_dup_data(int table_id, void **to, void **from, long argl, void* argp)
{
	struct fqdn_category_ctx *fqdn_cat=(struct fqdn_category_ctx *)(*from);
	pthread_mutex_lock(&(fqdn_cat->lock));
	fqdn_cat->ref_cnt++;
	pthread_mutex_unlock(&(fqdn_cat->lock));
	*to=fqdn_cat;

	return;
}

void fqdn_cat_new_data(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0,id=0,is_valid=0;

	struct fqdn_category_ctx *fqdn_cat = ALLOC(struct fqdn_category_ctx, 1);

	ret=sscanf(table_line, "%d\t%u\t%s\t%d\t%llu\t%d",&id, &fqdn_cat->fqdn_cat_id, fqdn_cat->fqdn, &fqdn_cat->match_method, &fqdn_cat->group_id, &is_valid);
	if(ret!=6)
	{
		FREE(&fqdn_cat);
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Parse fqdn category failed, ret: %d table_id: %d table_line: %s", ret, table_id, table_line);
		return;
	}
	fqdn_cat->ref_cnt=1;
	pthread_mutex_init(&(fqdn_cat->lock), NULL);

	*ad=fqdn_cat;
	return;
}

void fqdn_cat_free_data(int table_id, void **ad, long argl, void* argp)
{
	if(*ad==NULL)
	{
		return;
	}

	struct fqdn_category_ctx *fqdn_cat=(struct fqdn_category_ctx *)(*ad);
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

void fqdn_cat_table_free(struct fqdn_category_ctx *fqdn_cat)
{
	fqdn_cat_free_data(0, (void **)&fqdn_cat, 0, NULL);
}

void compile_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0, group_num=0;
	int config_id=0, service_id=0, action=0;
	int do_log=0,do_blacklist=0,is_valid=0;
	char effective_range[VERIFY_ARRAY_MAX]={0};
	char srv_def_large[VERIFY_STRING_MAX]={0};

	ret=sscanf(table_line, "%d\t%d\t%d\t%d\t%d\t%s\t%s\t%d\t%d", &config_id, &service_id, &action, &do_blacklist, &do_log,effective_range,srv_def_large,&group_num,&is_valid);
	if(ret!=9)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_MATCHER, "Security compile table parse failed, ret:%d, %s", ret, table_line);
		return;
	}
	do_log=do_log;
	do_blacklist=do_blacklist;
	is_valid=is_valid;

	struct rule_data_ctx *rule_ctx=ALLOC(struct rule_data_ctx, 1);
	rule_ctx->config_id=config_id;
	rule_ctx->action=action;
	rule_ctx->service_id=service_id;
	rule_ctx->ref_cnt=1;
	pthread_mutex_init(&(rule_ctx->lock), NULL);

	*ad = rule_ctx;
}

void compile_free_data(int table_id, void **ad, long argl, void* argp)
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

void compile_dup_data(int table_id, void **to, void **from, long argl, void* argp)
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

static enum policy_action decide_ctrl_action(int vsys_id, int compile_table_id, long long *results, size_t n_hit,
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

	hit_rules_ex=ALLOC(struct rule_data_ctx, n_hit);
	for (i = 0; i < n_hit && i<MAX_SCAN_RESULT; i++)
	{
		rule_ctx =(struct rule_data_ctx *)maat_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id],
																		g_policy_rt->plugin_table_id[compile_table_id],
																        (const char *)&results[i], sizeof(long long));
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
			if (hit_rules_ex[i].config_id > prior_rule->config_id)
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

void http_get_fqdn_cat_id(struct request_query_obj *query_obj, cJSON *attributeObj)
{
	int i=0;
	cJSON *sniCategory=NULL;

	if(!request_in_fqdn_cat(query_obj->table_id))
	{
		return;
	}

	sniCategory=cJSON_CreateArray();
	if(query_obj->table_id == TSG_OBJ_DST_SERVER_FQDN)
	{
		cJSON_AddItemToObject(attributeObj, "serverCategory", sniCategory);
	}
	else
	{
		cJSON_AddItemToObject(attributeObj, "sniCategory", sniCategory);
	}

	cJSON *fqdnObj=NULL;
	for(i=0; i<query_obj->fqdn_user.fqdn_cat_num; i++)
	{
		fqdnObj=cJSON_CreateObject();
		cJSON_AddItemToArray(sniCategory, fqdnObj);
		cJSON_AddNumberToObject(fqdnObj, "objectId", query_obj->fqdn_user.group_id[i]);
	}

	for(i=0; i<query_obj->fqdn_builtin.fqdn_cat_num; i++)
	{
		fqdnObj=cJSON_CreateObject();
		cJSON_AddItemToArray(sniCategory, fqdnObj);
		cJSON_AddNumberToObject(fqdnObj, "objectId", query_obj->fqdn_builtin.group_id[i]);
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
		if((strcasecmp(attri_name, "source") == 0) || (strcasecmp(attri_name, "internal") == 0))
		{
			cJSON_AddStringToObject(attributeObj, "ipGeoLocation",ip_ctx->location_client);
			ipAsn=cJSON_CreateArray();
			cJSON_AddItemToObject(attributeObj, "ipAsn", ipAsn);
			cJSON *ipAsnObj=NULL;
			for(i=0; i< 1; i++)
			{
				ipAsnObj=cJSON_CreateObject();
				cJSON_AddItemToArray(ipAsn, ipAsnObj);
				cJSON_AddStringToObject(ipAsnObj, "asn", ip_ctx->asn_client);
				cJSON_AddStringToObject(ipAsnObj, "organization", ip_ctx->organization_client);
			}
		}
		if((strcasecmp(attri_name, "destination") == 0) || (strcasecmp(attri_name, "external") == 0))
		{
			cJSON_AddStringToObject(attributeObj, "ipGeoLocation",ip_ctx->location_server);
			ipAsn=cJSON_CreateArray();
			cJSON_AddItemToObject(attributeObj, "ipAsn", ipAsn);
			cJSON *ipAsnObj=NULL;
			for(i=0; i< 1; i++)
			{
				ipAsnObj=cJSON_CreateObject();
				cJSON_AddItemToArray(ipAsn, ipAsnObj);
				cJSON_AddStringToObject(ipAsnObj, "asn", ip_ctx->asn_server);
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

int hit_path_is_duplicate(struct maat_hit_path *src, struct maat_hit_path dest, int result_cnt)
{
	for(int i = 0; i < result_cnt; i++)
	{
		if(src[i].item_id == dest.item_id && src[i].sub_group_id == dest.sub_group_id && src[i].top_group_id == dest.top_group_id)
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
		if(src[i].vtable_id == dest.vtable_id && src[i].top_group_id == dest.top_group_id)
		{
			return 1;
		}
	}
	return 0;
}

void http_get_scan_status(struct request_query_obj *query_obj, int compile_table_id, cJSON *attributes, cJSON  *data_obj, void *pme)
{
	int i=0, j=0, result_cnt=0;
	struct maat_hit_path result_hit_path[MAX_SCAN_RESULT]={0};
	cJSON *attributeObj=NULL,*hitPaths=NULL;
	cJSON *item = NULL;

	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *) pme;
	attributeObj=query_obj->attributes;

	if(ctx->tunnel_endpoint_x == 2)
	{
		/*temp repair**/
		if (ctx->tunnel_scan ==2 && ctx->tunnel_result[0] == 1 && ctx->tunnel_result[1] == 0)
		{
			item = cJSON_GetObjectItem(attributeObj, "attributeName");
			if(item && item->type==cJSON_String)
			{
				if(0 == strcasecmp(item->valuestring, "tunnel_endpointb"))
				{
					cJSON_Delete(attributeObj);
					return;
				}
			}
		}
		else
		{
			item = cJSON_GetObjectItem(attributeObj, "attributeName");
			if(item && item->type==cJSON_String)
			{
				if(0 == strcasecmp(item->valuestring, "tunnel_endpointa"))
				{
					cJSON_Delete(attributeObj);
					return;
				}
			}
		}
	}

	if(compile_table_id == TSG_TABLE_SECURITY && query_obj->table_id == TSG_OBJ_TUNNEL)
	{
		cJSON_DeleteItemFromObject(attributeObj, "attributeName");
		cJSON_AddStringToObject(attributeObj, "attributeName", "tunnel_endpoint_object");
		cJSON_DeleteItemFromObject(attributeObj, "attributeValue");
	}
	cJSON_AddItemToArray(attributes, attributeObj);

	hitPaths=cJSON_CreateArray();
	cJSON_AddItemToObject(attributeObj, "hitPaths", hitPaths);

	cJSON *histObj=NULL;
	for(i=0; i< ctx->n_read; i++)
	{
		for(j=0; j<=query_obj->merge_nth_scan_num; j++)
		{
			if (query_obj->merge_nth_scan[j] == ctx->hit_path[i].Nth_scan && query_obj->exclude_nth_scan[j] != 1)
			{
				if(ctx->hit_path[i].compile_id > 0)
				{
					if(hit_path_is_duplicate(result_hit_path, ctx->hit_path[i], result_cnt))
					{
						break;
					}
					else
					{
						memcpy(&result_hit_path[result_cnt], &ctx->hit_path[i], sizeof(struct maat_hit_path));
						result_cnt++;
					}
				}
				if(ctx->hit_path[i].item_id < 0)
				{
					continue;
				}
				histObj=cJSON_CreateObject();
				cJSON_AddItemToArray(hitPaths, histObj);
				cJSON_AddNumberToObject(histObj, "itemId", ctx->hit_path[i].item_id);
				cJSON_AddNumberToObject(histObj, "objectId", ctx->hit_path[i].sub_group_id);
				if (ctx->hit_path[i].top_group_id < 0)
				{
					ctx->hit_path[i].top_group_id = ctx->hit_path[i].sub_group_id;
				}
				cJSON_AddNumberToObject(histObj, "superiorObjectId", ctx->hit_path[i].top_group_id);
				break;
			}
		}
	}
	http_get_location_status(attributes, attributeObj, &ctx->ip_ctx);
	http_get_fqdn_cat_id(query_obj, attributeObj);
}

int policy_verify_regex_expression(const char *expression)
{
	return maat_helper_verify_regex_expression(expression);
}

static int get_ip_location_asn_table_name(struct ip_data_ctx *ip_ctx, int Nth_scan, cJSON *topObject)
{
	/*ip location**/
	int xret = 0, level=0;
	const char *client_table_name[]={"ATTR_SOURCE_GEO_COUNTRY", "ATTR_SOURCE_GEO_SUPER_ADMINISTRATIVE_AREA",
							 "ATTR_SOURCE_GEO_ADMINISTRATIVE_AREA", "ATTR_SOURCE_GEO_SUB_ADMINISTRATIVE_AREA"};
	const char *server_tabel_name[]={"ATTR_DESTINATION_GEO_COUNTRY", "ATTR_DESTINATION_GEO_SUPER_ADMINISTRATIVE_AREA",
							 "ATTR_DESTINATION_GEO_ADMINISTRATIVE_AREA", "ATTR_DESTINATION_GEO_SUB_ADMINISTRATIVE_AREA"}; 

	for(level = NTH_SCAN_IP_SRC_GEO_COUNTRY; level <= NTH_SCAN_IP_SRC_GEO_SUB_ADMINISTRATIVE_AREA; level++)
	{
		if(ip_ctx->Nth_scan[level] == Nth_scan)
		{
			cJSON_AddStringToObject(topObject, "tableName", client_table_name[level]);
			goto finish;
		}
	}

	for(level = NTH_SCAN_IP_DST_GEO_COUNTRY; level <= NTH_SCAN_IP_DST_GEO_SUB_ADMINISTRATIVE_AREA; level ++)
	{
		if(ip_ctx->Nth_scan[level] == Nth_scan)
		{
			cJSON_AddStringToObject(topObject, "tableName", server_tabel_name[level-NTH_SCAN_IP_DST_GEO_COUNTRY]);
			goto finish;
		}
	}
	if(ip_ctx->Nth_scan[NTH_SCAN_IP_SRC_ASN] == Nth_scan)
	{
		cJSON_AddStringToObject(topObject, "tableName", "ATTR_SOURCE_ASN");
		goto finish;
	}
	if(ip_ctx->Nth_scan[NTH_SCAN_IP_DST_ASN] == Nth_scan)
	{
		cJSON_AddStringToObject(topObject, "tableName", "ATTR_DESTINATION_ASN");
		goto finish;
	}
	if(ip_ctx->Nth_scan[NTH_SCAN_IP_INTERNAL_ASN] == Nth_scan)
	{
		cJSON_AddStringToObject(topObject, "tableName", "ATTR_INTERNAL_ASN");
		goto finish;
	}
	if(ip_ctx->Nth_scan[NTH_SCAN_IP_EXTERNAL_ASN] == Nth_scan)
	{
		cJSON_AddStringToObject(topObject, "tableName", "ATTR_EXTERNAL_ASN");
		goto finish;
	}
	return xret;
finish:
	xret = 1;
	return xret;
}

int get_attributes_table_name(struct request_query_obj *request, int num, int Nth_scan, struct ip_data_ctx *ip_ctx, int tunnel_endpoint_x, cJSON *topObject)
{
	int i=0, j=0;
	cJSON *attributeObj=NULL, *subchild=NULL;

	/*ip location**/
	if(get_ip_location_asn_table_name(ip_ctx, Nth_scan, topObject))
	{
		return 0;
	}

	for(i=0; i<num; i++)
	{
		for(j=0; j<= request[i].merge_nth_scan_num; j++)
		{
			if (request[i].merge_nth_scan[j] == Nth_scan)
			{
				attributeObj=request[i].attributes;
				subchild = cJSON_GetObjectItem(attributeObj, "tableName");
				if(subchild && subchild->type==cJSON_String)
				{
					cJSON_AddStringToObject(topObject, "tableName", subchild->valuestring);
				}
				break;
			}
		}
	}
	return 0;
}

int http_hit_policy_list(struct verify_policy_query *verify_policy, int num, size_t hit_cnt, cJSON *data_obj, void *pme)
{
	bool succeeded = false;
	size_t rules=0, i=0,j=0;
	int result_config[MAX_SCAN_RESULT] = {0};

	int vsys_id = verify_policy->vsys_id;
	int compile_table_id = verify_policy->compile_table_id;

	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *) pme;

	hit_cnt = ctx->hit_cnt;
	if (hit_cnt <= 0)
	{
		return 0;
	}

	if (hit_cnt >= MAX_SCAN_RESULT)	hit_cnt = MAX_SCAN_RESULT;

	ctx->action = decide_ctrl_action(vsys_id, compile_table_id, ctx->result, hit_cnt, &ctx->enforce_rules, &ctx->n_enforce, &ctx->hit_rules);
	ctx->hit_cnt = hit_cnt;
	cJSON *hit_obj=NULL, *policy_obj=NULL;
	cJSON *topObjectList=NULL, *topObject=NULL;
	hit_obj=cJSON_CreateArray();
	cJSON_AddItemToObject(data_obj, "hitPolicyList", hit_obj);
	if (ctx->hit_cnt >= 1)
	{
		for (i = 0; i < ctx->hit_cnt; i++)
		{
			if(http_hit_policy_match(result_config, i, ctx->hit_rules[i].config_id))
			{
				continue;
			}
			succeeded = false;
			policy_obj=cJSON_CreateObject();
			cJSON_AddNumberToObject(policy_obj, "id",ctx->hit_rules[i].config_id);
			cJSON_AddStringToObject(policy_obj, "policyName", "");

			for (rules = 0; rules < ctx->n_enforce; rules++)
			{
				if (ctx->enforce_rules[rules].config_id == ctx->hit_rules[i].config_id)
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
			result_config[i] = ctx->hit_rules[i].config_id;
			struct maat_hit_path result_hit_path[MAX_SCAN_RESULT]={0}; int result_cnt=0;

			topObjectList=cJSON_CreateArray();
			cJSON_AddItemToObject(policy_obj, "topObjectList", topObjectList);
			for(j=0; j<=(size_t)ctx->n_read; j++)
			{
				if(ctx->hit_path[j].compile_id > 0 && ctx->hit_path[j].compile_id == ctx->hit_rules[i].config_id)
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
					#if 0
					if(http_hit_policy_match(result_object_id, j, ctx->hit_path[j].top_group_id))
					{
						continue;
					}
					#endif
					topObject=cJSON_CreateObject();
					cJSON_AddNumberToObject(topObject, "objectId", ctx->hit_path[j].top_group_id);
					cJSON_AddNumberToObject(topObject, "notFlag", ctx->hit_path[j].NOT_flag);
					cJSON_AddNumberToObject(topObject, "nthClause", ctx->hit_path[j].clause_index);
					get_attributes_table_name(verify_policy->request_object, num, ctx->hit_path[j].Nth_scan, &ctx->ip_ctx, ctx->tunnel_endpoint_x, topObject);
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

static int group_scan(struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt, struct maat_hit_group hit_group, int table_id, int logic)
{
	size_t n_hit_result=0;
	int scan_ret=0, hit_cnt_group=0;

	scan_ret = maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &hit_group, 1,
							   ctx->result+hit_cnt+hit_cnt_group, MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_group+=n_hit_result;
	}

	if(logic)
	{
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_group,
								   MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_group+=n_hit_result;
		}
	}
	return hit_cnt_group;
}


static int get_group_id_by_location(const struct ip_data_table* ip_location, size_t level)
{
    const int* group_ids[] = {
		&ip_location->country_region_group_id,
        &ip_location->province_group_id,
        &ip_location->city_group_id,
        &ip_location->subdivision_group_id
    };

    if (level >= 0 && level < sizeof(group_ids) / sizeof(group_ids[0]))
    {
        return *group_ids[level];
    }

    return 0;
}

int ip_location_scan(struct policy_scan_ctx *ctx, int vsys_id, struct ip_addr *sip, struct ip_addr *dip, int hit_cnt)
{
	int scan_ret=0, hit_cnt_ip=0;
	char buff[VERIFY_STRING_MAX * 2]={0};
	struct maat_hit_group hit_group;
	struct maat_hit_path hit_path[HIT_PATH_SIZE];
	struct ip_data_table* ip_location_client=NULL, *ip_location_server=NULL;

	if(!g_policy_rt->load_ip_location)
	{
		return 0;
	}

	memset(hit_path, 0, sizeof(struct maat_hit_path)*HIT_PATH_SIZE);
	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_LOCATION_USER_DEFINED], sip, (void **)&ip_location_client, 1);
	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_LOCATION_USER_DEFINED], dip, (void **)&ip_location_server, 1);

	if (ip_location_client == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_LOCATION_BUILT_IN], sip,(void **)&ip_location_client, 1);
	}
	if (ip_location_server == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_LOCATION_BUILT_IN], dip, (void **)&ip_location_server, 1);
	}

	if(ip_location_server!=NULL)
	{
		memset(buff,0,sizeof(buff));
		snprintf(buff, sizeof(buff), "%s.%s.%s.%s", ip_location_server->country_full, ip_location_server->province_full, ip_location_server->city_full, ip_location_server->subdivision_addr);
		ctx->ip_ctx.location_server=strdup(buff);
		
		for(int level=0; level < 4; level++)
		{
			memset(&hit_group, 0, sizeof(hit_group));
			hit_group.group_id=get_group_id_by_location(ip_location_server, level);
			if(hit_group.group_id <= 0)
			{
				continue;
			}
			
			scan_ret = group_scan(ctx, vsys_id, hit_cnt, hit_group, TSG_OBJ_IP_DST_GEO_COUNTRY+level, 1);
			if(scan_ret > 0)
			{
				hit_cnt_ip+=scan_ret; 
			}
			ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);
			ctx->ip_ctx.Nth_scan[NTH_SCAN_IP_DST_GEO_COUNTRY+level] = maat_state_get_scan_count(ctx->scan_mid);		
		}
	}
	if(ip_location_client!=NULL)
	{
		memset(buff,0,sizeof(buff));
		snprintf(buff, sizeof(buff), "%s.%s.%s.%s", ip_location_client->country_full, ip_location_client->province_full, ip_location_client->city_full, ip_location_client->subdivision_addr);
		ctx->ip_ctx.location_client=strdup(buff);

		for(int level=0; level < 4; level++)
		{
			memset(&hit_group, 0, sizeof(hit_group));
			hit_group.group_id=get_group_id_by_location(ip_location_client, level);
			if(hit_group.group_id <= 0)
			{
				continue;
			}

			scan_ret = group_scan(ctx, vsys_id, hit_cnt, hit_group, TSG_OBJ_IP_SRC_GEO_COUNTRY+level, 1);
			if(scan_ret > 0)
			{
				hit_cnt_ip+=scan_ret; 	
			}
			ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);
			ctx->ip_ctx.Nth_scan[NTH_SCAN_IP_SRC_GEO_COUNTRY+level] = maat_state_get_scan_count(ctx->scan_mid);	
		}
	}

	if(ip_location_server)
		ip_table_free(ip_location_server);
	if(ip_location_client)
		ip_table_free(ip_location_client);
	return hit_cnt_ip;
}

int ip_asn_scan(struct policy_scan_ctx * ctx, int vsys_id, int table_id, struct ip_addr* sip, struct ip_addr* dip, int hit_cnt)
{
	size_t n_hit_result=0;
	int scan_ret=0, hit_cnt_ip=0, Nth_scan_cnt=0;
	struct maat_hit_path hit_path[HIT_PATH_SIZE];
	struct ip_data_table* ip_asn_client=NULL, *ip_asn_server=NULL;

	if(!g_policy_rt->load_ip_location)
	{
		return 0;
	}
	
	memset(hit_path, 0, sizeof(struct maat_hit_path)*HIT_PATH_SIZE);
	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_ASN_USER_DEFINED], sip, (void **)&ip_asn_client, 1);
	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_ASN_USER_DEFINED], dip, (void **)&ip_asn_server, 1);

	if (ip_asn_client == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_ASN_BUILT_IN], sip,(void **)&ip_asn_client, 1);
	}
	if (ip_asn_server == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_ASN_BUILT_IN], dip,(void **)&ip_asn_server, 1);
	}

	struct maat_hit_group hit_group;
	if(ip_asn_server!=NULL)
	{
		ctx->ip_ctx.asn_server=strdup(ip_asn_server->asn);
		ctx->ip_ctx.organization_server=strdup(ip_asn_server->organization);

		memset(&hit_group, 0, sizeof(hit_group));
		hit_group.group_id=ip_asn_server->asn_group_id;

		if(table_id == TSG_OBJ_DESTINATION_ADDR)
		{
			table_id = TSG_OBJ_IP_DST_ASN;
		}
		else
		{
			table_id = (table_id==TSG_OBJ_INTERNAL_ADDR)?TSG_OBJ_INTERNAL_ASN:TSG_OBJ_EXTERNAL_ASN;
		}
	    scan_ret=maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &hit_group, 1,
						    	 ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		if(scan_ret >= MAAT_SCAN_OK)
		{
			ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);
			if(table_id ==	TSG_OBJ_IP_DST_ASN)
			{
				ctx->ip_ctx.Nth_scan[NTH_SCAN_IP_DST_ASN] = maat_state_get_scan_count(ctx->scan_mid);
			}
			else
			{
				Nth_scan_cnt = (table_id == TSG_OBJ_INTERNAL_ASN) ? NTH_SCAN_IP_INTERNAL_ASN : NTH_SCAN_IP_EXTERNAL_ASN;
				ctx->ip_ctx.Nth_scan[Nth_scan_cnt] = maat_state_get_scan_count(ctx->scan_mid);
			}
		}
	}
	if(ip_asn_client!=NULL)
	{
		ctx->ip_ctx.asn_client=strdup(ip_asn_client->asn);
		ctx->ip_ctx.organization_client=strdup(ip_asn_client->organization);

		memset(&hit_group, 0, sizeof(hit_group));
		hit_group.group_id=ip_asn_client->asn_group_id;

		if(table_id == TSG_OBJ_SOURCE_ADDR)
		{
			table_id = TSG_OBJ_IP_SRC_ASN;
		}
		else
		{
			table_id = (table_id==TSG_OBJ_INTERNAL_ADDR)?TSG_OBJ_INTERNAL_ASN:TSG_OBJ_EXTERNAL_ADDR;
		}
		scan_ret=maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &hit_group, 1,
								ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		if(scan_ret >= MAAT_SCAN_OK)
		{
			ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);

			if(table_id == TSG_OBJ_IP_SRC_ASN)
			{
				ctx->ip_ctx.Nth_scan[NTH_SCAN_IP_SRC_ASN] = maat_state_get_scan_count(ctx->scan_mid);
			}
			else
			{
				Nth_scan_cnt = (table_id == TSG_OBJ_INTERNAL_ASN) ? NTH_SCAN_IP_INTERNAL_ASN : NTH_SCAN_IP_EXTERNAL_ASN;
				ctx->ip_ctx.Nth_scan[Nth_scan_cnt] = maat_state_get_scan_count(ctx->scan_mid);
			}
		}
	}
	if(ip_asn_server)
		ip_table_free(ip_asn_server);
	if(ip_asn_client)
		ip_table_free(ip_asn_client);
	return hit_cnt_ip;
}

int get_fqdn_category_id(struct request_query_obj *request, struct policy_scan_ctx * ctx, int vsys_id, const char *fqdn, int table_id, int hit_cnt)
{
	int j=0, k=0;
	size_t n_read=0, n_hit_result=0;
	int hit_path_cnt=0;
	int i=0,ret=0, hit_cnt_fqdn=0;
	struct fqdn_category_ctx *fqdn_cat_user[8]={0},*fqdn_cat_built[8]={0};

	if(!g_policy_rt->load_fqdn_cat)
	{
		return 0;
	}

	ret=maat_fqdn_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_FQDN_CAT_USER_DEFINED], fqdn, (void **)fqdn_cat_user, 8);
	for(i=0; i <ret; i++)
	{
		if(i < 8)
		{
			if(http_hit_policy_match((int *)(request->fqdn_user.group_id), j, (int)fqdn_cat_user[i]->group_id))
			{
				continue;
			}
			request->fqdn_user.group_id[j] = fqdn_cat_user[i]->group_id;
			j++;
		}
		fqdn_cat_table_free(fqdn_cat_user[i]);
	}
	request->fqdn_user.fqdn_cat_num = j< 8 ? j : 8;

	ret=maat_fqdn_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_FQDN_CAT_BUILT_IN], fqdn, (void **)fqdn_cat_built, 8);
	for(i=0; i <ret; i++)
	{
		if(i < 8)
		{
			if(http_hit_policy_match((int *)(request->fqdn_builtin.group_id), k, (int)fqdn_cat_built[i]->group_id))
			{
				continue;
			}
			request->fqdn_builtin.group_id[k] = fqdn_cat_built[i]->group_id;
			k++;
		}
		fqdn_cat_table_free(fqdn_cat_built[i]);
	}
	request->fqdn_builtin.fqdn_cat_num  = k < 8 ? k : 8;
	struct maat_hit_group hit_group;

	if(request->fqdn_user.fqdn_cat_num > 0)
	{
		for(i=0; i<request->fqdn_user.fqdn_cat_num; i++)
		{
			memset(&hit_group, 0, sizeof(hit_group));
			hit_group.group_id=request->fqdn_user.group_id[i];
	    	ret=maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &hit_group, 1,
							    ctx->result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if(ret == MAAT_SCAN_HIT)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								  	  ctx->result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if (ret == MAAT_SCAN_HIT)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			if(ret >= MAAT_SCAN_OK)
			{
				request->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);;
				request->exclude_nth_scan[hit_path_cnt] = 1;
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
		goto finish;
	}
	if (request->fqdn_builtin.fqdn_cat_num > 0)
	{
		for(i=0; i<request->fqdn_builtin.fqdn_cat_num; i++)
		{
			memset(&hit_group, 0, sizeof(hit_group));
			hit_group.group_id=request->fqdn_builtin.group_id[i];
			ret=maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &hit_group, 1,
							    ctx->result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if(ret>0)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_fqdn,
								      MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if (ret == MAAT_SCAN_HIT)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			if(ret >= MAAT_SCAN_OK)
			{
				request->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);
				request->exclude_nth_scan[hit_path_cnt] = 1;
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
	}
finish:
	request->merge_nth_scan_num = hit_path_cnt;
	return hit_cnt_fqdn;
}

int tunnel_level_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read, hit_path_cnt=0;
	int scan_ret=0, hit_cnt_tunnel=0;
	struct maat_hit_group hit_group;
	int group_level_array[]={50, 51, 52, 53, 54, 55, 56, 57};

	memset(&hit_group, 0, sizeof(hit_group));
	hit_group.group_id=group_level_array[request->numeric];
	scan_ret = group_scan(ctx, vsys_id, hit_cnt, hit_group, request->table_id, 1);
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

int get_tunnel_type_table_id(char *tunnel_type)
{
	int table_id=TSG_OBJ_TUNNEL_GTP_ENDPOINT;
	size_t i = 0;
	const char *tunnel_type_map[] = {"GTP", "GRE", "IPv4/IPv6"};

	if(tunnel_type == NULL)
	{
		return table_id;
	}

	for (i = 0; i < sizeof(tunnel_type_map) / sizeof(const char *); i++)
	{
		if (0 == strcasecmp(tunnel_type, tunnel_type_map[i]))
		{
			if(i == 0)
			{
				table_id = TSG_OBJ_TUNNEL_GTP_ENDPOINT;
			}
			if(i == 1)
			{
				table_id = TSG_OBJ_TUNNEL_GRE_ENDPOINT;
			}
			if(i == 2)
			{
				table_id = TSG_OBJ_TUNNEL_IP_IN_IP_ENDPOINT;
			}
			break;
		}			
	}
	return table_id;
}

int tunnel_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt, struct ipaddr *ip_addr)
{
	int logic =1;
	int i=0,hit_path_cnt=0;
	int n_read=0, hit_cnt_endpoint=0;
	struct maat_hit_group hit_group;
	int scan_ret=0, hit_cnt_tunnel=0;
	size_t n_hit_result=0;
	long long result[MAX_SCAN_RESULT]={0};

	int hit_cnt_group=0;

	if(ctx->tunnel_scan_mid == NULL)
	{
		ctx->tunnel_scan_mid = maat_state_new(g_policy_rt->feather[vsys_id], ctx->thread_id);
		maat_state_set_scan_compile_table(ctx->tunnel_scan_mid, g_policy_rt->compile_table_id[TSG_TUNNEL]);
	}
	
	int tunnel_table_id = get_tunnel_type_table_id(request->tunnel_type);
	if (ip_addr->addrtype == ADDR_TYPE_IPV4)
	{
		scan_ret = maat_scan_ipv4_port(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[tunnel_table_id], ip_addr->v4->saddr, ip_addr->v4->source, 
			 					  	   result, MAX_SCAN_RESULT, &n_hit_result, ctx->tunnel_scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_endpoint+=n_hit_result;
		}
	}
	
	if (ip_addr->addrtype == ADDR_TYPE_IPV6)
	{
		scan_ret = maat_scan_ipv6_port(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[tunnel_table_id], ip_addr->v6->saddr, ip_addr->v6->source,
									   result, MAX_SCAN_RESULT, &n_hit_result, ctx->tunnel_scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_endpoint+=n_hit_result;
		}
	}

	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[tunnel_table_id], result, MAX_SCAN_RESULT,
									&n_hit_result, ctx->tunnel_scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_endpoint+=n_hit_result;
	}

	if(hit_cnt_endpoint < 0)
	{
		goto finish;
	}

	for(i = 0; i< hit_cnt_endpoint; i++)
	{
		memset(&hit_group, 0, sizeof(hit_group));
		hit_group.group_id=result[i];
		if(hit_group.group_id != 0)
		{
			if(ctx->tunnel_endpoint_x == 2 && ctx->tunnel_scan == 0)
			{
				logic=0;
			}
			scan_ret = maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_TUNNEL], &hit_group, 1,
							   		  ctx->result+hit_cnt+hit_cnt_group, MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
			if(scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_tunnel+=n_hit_result;
			}
			if(scan_ret >= MAAT_SCAN_OK)
			{
				ctx->tunnel_result[ctx->tunnel_scan]=1;
				n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
				request->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
	}
	if(logic)
	{
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_TUNNEL], ctx->result+hit_cnt+hit_cnt_group,
								   MAX_SCAN_RESULT-hit_cnt-hit_cnt_group, &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_tunnel+=n_hit_result;
		}
	}

	ctx->tunnel_scan++;
	request->merge_nth_scan_num = hit_path_cnt;
finish:
	return hit_cnt_tunnel;
}

static int app_id_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_app_id=0;
	struct app_id_dict *app_dict=NULL;
	struct maat_hit_group hit_group;

	app_dict = (struct app_id_dict*)maat_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[PROFILE_APP_DI_DICT], (const char *)&(request->numeric), sizeof(long long));
	if(app_dict==NULL)
	{
		return 0;
	}
	memset(&hit_group, 0, sizeof(hit_group));
	hit_group.group_id=app_dict->group_id;
	scan_ret = group_scan(ctx, vsys_id, hit_cnt, hit_group, request->table_id, 1);
	if(scan_ret > 0)
	{
		hit_cnt_app_id += scan_ret;
	}
	app_id_dict_free(app_dict);
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_app_id;
}

static int flag_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_flag=0;
	size_t n_hit_result=0;

	int flag=request->numeric;
	int table_id = request->table_id;

	scan_ret=maat_scan_flag(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
							flag, ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt,
						    &n_hit_result, ctx->scan_mid);
	if(scan_ret==MAAT_SCAN_HIT)
	{
		hit_cnt_flag+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt,
								   &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_flag+=n_hit_result;
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_flag;
}

static int http_hdr_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_hdr=0;
	size_t n_hit_result=0;

	if(!request->district || !request->string)
	{
		return hit_cnt_hdr;
	}

	int table_id = request->table_id;
	const char *value = request->string;
	const char * str_field_name = request->district;
	maat_state_set_scan_district(ctx->scan_mid, g_policy_rt->scan_table_id[table_id], str_field_name, strlen(str_field_name));
	scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								value, strlen(value), ctx->result + hit_cnt, MAX_SCAN_RESULT - hit_cnt,
		 					    &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_hdr += n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result + hit_cnt, MAX_SCAN_RESULT - hit_cnt,
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
static int get_group_id_by_protocol(int protocol)
{
	int group_id = 0;
	switch(protocol)
	{
		case PROCOCOL_ANY:
			group_id = PROTOCOL_ANY_GROUP_ID;
			break;
		case PROTOCOL_ICMP:
			group_id = PROTOCOL_ICMP_GROUP_ID;
			break;
		case PROCOCOL_TCP:
			group_id = PROTOCOL_TCP_GROUP_ID;
			break;
		case PROCOCOL_UDP:
			group_id = PROTOCOL_UDP_GROUP_ID;
			break;
		default:
			group_id = 0;
			break;
	}
	return group_id;
}

static int protocol_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_protocol=0;
	struct maat_hit_group hit_group;

	memset(&hit_group, 0, sizeof(hit_group));
	hit_group.group_id=get_group_id_by_protocol(request->numeric);
	if(hit_group.group_id != 0 && ctx->ip_protocol_num == 0)
	{
		scan_ret = group_scan(ctx, vsys_id, hit_cnt, hit_group, TSG_OBJ_IP_PROTOCOL, 1);
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

static int ip_addr_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_ip=0;
	size_t n_hit_result=0;
	int table_id = request->table_id;

	if (request->ip_addr->addrtype == ADDR_TYPE_IPV4)
	{
		if(0 == strcasecmp(request->attri_name, "source") || 0 == strcasecmp(request->attri_name, "internal"))
		{
			scan_ret = maat_scan_ipv4_port(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], request->ip_addr->v4->saddr, request->ip_addr->v4->source, 
			 						      ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if(scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  	  &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
		}
		if(0 == strcasecmp(request->attri_name, "destination") || 0 == strcasecmp(request->attri_name, "external"))
		{
			scan_ret = maat_scan_ipv4_port(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], request->ip_addr->v4->daddr, request->ip_addr->v4->dest, 
			 						       ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if(scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
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
		if(0 == strcasecmp(request->attri_name, "source") || 0 == strcasecmp(request->attri_name, "internal"))
		{
			scan_ret = maat_scan_ipv6_port(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], request->ip_addr->v6->saddr,request->ip_addr->v6->source,
									       ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  	  &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
		}
		if(0 == strcasecmp(request->attri_name, "destination") || 0 == strcasecmp(request->attri_name, "external"))
		{
			scan_ret = maat_scan_ipv6_port(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], request->ip_addr->v6->daddr,request->ip_addr->v6->dest,
									       ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
			if (scan_ret == MAAT_SCAN_HIT)
			{
				hit_cnt_ip+=n_hit_result;
			}
			scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
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

static int ssl_extension_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_ssl=0;
	struct maat_hit_group hit_group;

	memset(&hit_group, 0, sizeof(hit_group));
	hit_group.group_id=(request->numeric == 1 ? BOOLEAN_TRUE_GROUP_ID : BOOLEAN_FLASE_GROUP_ID);
	scan_ret =group_scan(ctx, vsys_id, hit_cnt, hit_group, request->table_id, 1);
	if(scan_ret > 0)
	{
		hit_cnt_ssl += scan_ret;
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_ssl;
}

static int port_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_port=0;
	size_t n_hit_result=0;
	int table_id = request->table_id;
	int port = atoi(request->string);

	scan_ret=maat_scan_integer(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], port, ctx->result+hit_cnt+hit_cnt_port,
							   MAX_SCAN_RESULT-hit_cnt-hit_cnt_port, &n_hit_result, ctx->scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_port+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt+hit_cnt_port,
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

size_t policy_verify_scan(int vsys_id, int compile_table_id, struct request_query_obj *request, void *pme)
{
	size_t n_hit_result=0;
	int scan_ret=0, n_read;

	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *) pme;
	size_t hit_cnt = ctx->hit_cnt;

	int table_id = request->table_id;
	const char *value = request->string;

	switch (table_id)
	{
		case TSG_OBJ_SOURCE_ADDR:
		case TSG_OBJ_DESTINATION_ADDR:
		case TSG_OBJ_INTERNAL_ADDR:
		case TSG_OBJ_EXTERNAL_ADDR:
			if(request->ip_addr == NULL)
			{
				goto decide;
			}
			struct ip_addr dest_ip, source_ip;
			ip_addr_to_address(request->ip_addr, &dest_ip, &source_ip);

			scan_ret = ip_location_scan(ctx, vsys_id, &source_ip, &dest_ip, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			scan_ret = ip_asn_scan(ctx, vsys_id, table_id, &source_ip, &dest_ip, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			scan_ret = ip_addr_scan(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_IP_PROTOCOL:
			scan_ret = protocol_scan(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_SOURCE_PORT:
		case TSG_OBJ_DESTINATION_PORT:
		case TSG_OBJ_INTERNAL_PORT:
		case TSG_OBJ_EXTERNAL_PORT:
			scan_ret = port_scan(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_TUNNEL_LEVEL:
			scan_ret = tunnel_level_scan(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+= scan_ret;
			}
			goto decide;
		case TSG_OBJ_TUNNEL:
			memset(&dest_ip, 0, sizeof(dest_ip));
			memset(&source_ip, 0, sizeof(source_ip));
			ip_addr_to_address(request->ip_addr, &dest_ip, &source_ip);
			scan_ret = tunnel_scan(request, ctx, vsys_id, hit_cnt, request->ip_addr);
			if(scan_ret)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_APP_ID:
			scan_ret = app_id_scan(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_FLAG:
			scan_ret = flag_scan(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_HTTP_REQ_HDR:
		case TSG_OBJ_HTTP_RES_HDR:
			scan_ret = http_hdr_scan(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_SSL_ECH:
		case TSG_OBJ_SSL_ESNI:
		case TSG_OBJ_SSL_NO_SNI:
			scan_ret = ssl_extension_scan(request, ctx, vsys_id, hit_cnt);
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
		/*TSG_HOST, TSG_HOST+1=TSG_HOST_CAT**/
		scan_ret = get_fqdn_category_id(request, ctx, vsys_id, value, table_id+1, hit_cnt);
		if(scan_ret>0)
		{
			hit_cnt+=scan_ret;
		}
	}
	
	scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								value, strlen(value), ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt,
						 	    &n_hit_result, ctx->scan_mid);
	if(scan_ret==MAAT_SCAN_HIT)
	{
		hit_cnt+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt,
								   &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt+=n_hit_result;
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[request->merge_nth_scan_num] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
decide:
	ctx->hit_cnt = hit_cnt;
	return hit_cnt;
}

static struct maat *create_maat_feather(const char * instance_name, const char * profile, const char * section, int max_thread, char *log_path, int db_index)
{
	struct maat *target=NULL;
	int input_mode = 0, maat_perf_on = 0, log_level=0;
	int ret = 0, maat_stat_on = 0, effect_interval = 60;
	char table_info[VERIFY_STRING_MAX] = {0}, inc_cfg_dir[VERIFY_STRING_MAX] = {0}, ful_cfg_dir[VERIFY_STRING_MAX] = {0};
	char json_cfg_file[VERIFY_STRING_MAX] = {0}, maat_stat_file[VERIFY_PATH_MAX] = {0};
	char redis_ip[VERIFY_STRING_MAX] = {0}, redis_port_range[VERIFY_STRING_MAX] = {0};
	char accept_tags[VERIFY_STRING_MAX] = {0}, maat_stat_db_file[VERIFY_PATH_MAX] = {0};
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
		case MAAT_INPUT_FILE:
			maat_options_set_iris(opts, ful_cfg_dir, inc_cfg_dir);
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
		snprintf(maat_stat_db_file, VERIFY_PATH_MAX, "%s.%d", maat_stat_file, db_index);
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

static void http_table_name_init(const char *table_name[__TSG_OBJ_MAX])
{
	table_name[TSG_OBJ_HTTP_URL] = "ATTR_HTTP_URL";
	table_name[TSG_OBJ_HTTP_REQ_HDR] =  "ATTR_HTTP_REQ_HDR";
	table_name[TSG_OBJ_HTTP_REQ_BODY] =  "ATTR_HTTP_REQ_BODY";
	table_name[TSG_OBJ_HTTP_RES_HDR] =  "ATTR_HTTP_RES_HDR";
	table_name[TSG_OBJ_HTTP_RES_BODY] = "ATTR_HTTP_RES_BODY";
	table_name[TSG_OBJ_SSL_CN] =  "ATTR_SSL_CN";
	table_name[TSG_OBJ_SSL_CN_CAT] = "ATTR_SSL_CN_CAT";
	table_name[TSG_OBJ_SSL_SAN] = "ATTR_SSL_SAN";
	table_name[TSG_OBJ_SSL_SAN_CAT] = "ATTR_SSL_SAN_CAT";
	return;
}

static void doq_table_name_init(const char *table_name[__TSG_OBJ_MAX])
{
	table_name[TSG_OBJ_DNS_QNAME]="ATTR_DNS_QNAME";
	table_name[TSG_OBJ_DOH_QNAME] = "ATTR_DOH_QNAME";
	return;
}

static void mail_table_name_int(const char *table_name[__TSG_OBJ_MAX])
{
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
	return;
}

static void common_table_name_int(const char *table_name[__TSG_OBJ_MAX])
{
	table_name[TSG_OBJ_SIP_FROM]="ATTR_SIP_ORIGINATOR_DESCRIPTION";
	table_name[TSG_OBJ_SIP_TO]="ATTR_SIP_RESPONDER_DESCRIPTION";
	table_name[TSG_OBJ_IMSI]="ATTR_GTP_IMSI";
	table_name[TSG_OBJ_PHONE_NUMBER]="ATTR_GTP_PHONE_NUMBER";
	table_name[TSG_OBJ_APN]="ATTR_GTP_APN";
	table_name[TSG_OBJ_TUNNEL]="ATTR_TUNNEL",
	table_name[TSG_OBJ_FLAG]="ATTR_FLAG";
	table_name[TSG_OBJ_GTP_IMEI]="ATTR_GTP_IMEI";
	table_name[TSG_OBJ_IP_SRC_ASN]="ATTR_SOURCE_ASN";
	table_name[TSG_OBJ_IP_DST_ASN]="ATTR_DESTINATION_ASN";
	table_name[TSG_OBJ_IP_SRC_GEO_COUNTRY]="ATTR_SOURCE_GEO_COUNTRY";
	table_name[TSG_OBJ_IP_SRC_GEO_SUPER_ADMINISTRATIVE_AREA]="ATTR_SOURCE_GEO_SUPER_ADMINISTRATIVE_AREA";
	table_name[TSG_OBJ_IP_SRC_GEO_ADMINISTRATIVE_AREA]="ATTR_SOURCE_GEO_ADMINISTRATIVE_AREA";
	table_name[TSG_OBJ_IP_SRC_GEO_SUB_ADMINISTRATIVE_AREA]="ATTR_SOURCE_GEO_SUB_ADMINISTRATIVE_AREA";
	table_name[TSG_OBJ_IP_DST_GEO_COUNTRY]="ATTR_DESTINATION_GEO_COUNTRY";
	table_name[TSG_OBJ_IP_DST_GEO_SUPER_ADMINISTRATIVE_AREA]="ATTR_DESTINATION_GEO_SUPER_ADMINISTRATIVE_AREA";
	table_name[TSG_OBJ_IP_DST_GEO_ADMINISTRATIVE_AREA]="ATTR_DESTINATION_GEO_ADMINISTRATIVE_AREA";
	table_name[TSG_OBJ_IP_DST_GEO_SUB_ADMINISTRATIVE_AREA]="ATTR_DESTINATION_GEO_SUB_ADMINISTRATIVE_AREA";
	table_name[TSG_OBJ_DST_SERVER_FQDN]="ATTR_SERVER_FQDN";
	table_name[TSG_OBJ_DST_SERVER_FQDN_CAT]="ATTR_SERVER_FQDN_CAT";
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
	table_name[TSG_OBJ_INTERNAL_ASN]="ATTR_INTERNAL_ASN";
	table_name[TSG_OBJ_EXTERNAL_ASN]="ATTR_EXTERNAL_ASN";
	table_name[TSG_OBJ_TUNNEL_GTP_ENDPOINT]="ATTR_TUNNEL_GTP_ENDPOINT";
	table_name[TSG_OBJ_TUNNEL_GRE_ENDPOINT]="ATTR_TUNNEL_GRE_ENDPOINT";
	table_name[TSG_OBJ_TUNNEL_IP_IN_IP_ENDPOINT]="ATTR_TUNNEL_IP_IN_IP_ENDPOINT";
	return;
}

int maat_complie_plugin_table_init(int vsys_id, int compile_type_id)
{
	int table_id=0;
	const char *table_name=NULL;

	const char *conjunction_table_name_map[] = {"SECURITY_COMPILE_CONJUNCTION", "PXY_CTRL_COMPILE_CONJUNCTION", "TRAFFIC_SHAPING_COMPILE_CONJUNCTION",
												"SERVICE_CHAINING_COMPILE_CONJUNCTION", "PXY_INTERCEPT_COMPILE_CONJUNCTION","STATISTICS_COMPILE_CONJUNCTION", 
												"MONITOR_COMPILE_CONJUNCTION", "DOS_PROTECTION_COMPILE_CONJUNCTION", "TUNNEL_COMPILE_CONJUNCTION"};

	table_name = conjunction_table_name_map[compile_type_id];
	table_id=g_policy_rt->compile_table_id[compile_type_id]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id < 0)
	{
		return table_id;
	}

	const char *plugin_table_name_map[] = {"SECURITY_COMPILE_PLUGIN", "PXY_CTRL_COMPILE_PLUGIN", "TRAFFIC_SHAPING_COMPILE_PLUGIN",
											"SERVICE_CHAINING_COMPILE_PLUGIN", "PXY_INTERCEPT_COMPILE_PLUGIN", "STATISTICS_COMPILE_PLUGIN",
											"MONITOR_COMPILE_PLUGIN", "DOS_PROTECTION_COMPILE_PLUGIN", "TUNNEL_COMPILE_PLUGIN"};

	table_name = plugin_table_name_map[compile_type_id];
	table_id = g_policy_rt->plugin_table_id[compile_type_id]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id >=0 )
	{
		maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, compile_table_new_cb, compile_free_data, compile_dup_data, 0,NULL);
	}
	return table_id;
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

int maat_table_init(struct verify_policy * verify, const char* profile_path)
{
	int ret = -1; int vsys_id=0;
	int load_vsys_num=0, load_start_vsys=0;
	char log_path[VERIFY_PATH_MAX];

	snprintf(log_path, sizeof(log_path), "logs/maat.log");
	g_policy_rt = ALLOC(struct verify_policy_rt, 1);
	g_policy_rt->local_logger = verify->logger;
	g_policy_rt->thread_num = verify->nr_work_threads;

	MESA_load_profile_int_def(profile_path, "MAAT", "load_ip_location", &(g_policy_rt->load_ip_location), 1);
	MESA_load_profile_int_def(profile_path, "MAAT", "load_fqdn_cat", &(g_policy_rt->load_fqdn_cat), 1);
	MESA_load_profile_int_def(profile_path, "MAAT", "load_vsys_num", &(load_vsys_num), 255);
	MESA_load_profile_int_def(profile_path, "MAAT", "load_start_vsys", &(load_start_vsys), 0);
	load_vsys_num = load_vsys_num > VSYS_ID_MAX ? VSYS_ID_MAX : load_vsys_num;
	load_start_vsys = load_start_vsys > load_vsys_num ? 0 : load_start_vsys;

	for(vsys_id=load_start_vsys; vsys_id < load_vsys_num; vsys_id++)
	{
		g_policy_rt->feather[vsys_id] = create_maat_feather("static", profile_path, "MAAT", g_policy_rt->thread_num, log_path, vsys_id);
		if (!g_policy_rt->feather[vsys_id])
		{
			goto error_out;
		}
		const char * table_name[__TSG_OBJ_MAX];
		table_name[TSG_OBJ_SOURCE_ADDR] = "ATTR_SOURCE_IP";
		table_name[TSG_OBJ_DESTINATION_ADDR]="ATTR_DESTINATION_IP";
		table_name[TSG_OBJ_SUBSCRIBE_ID] = "ATTR_SUBSCRIBER_ID";
		table_name[TSG_OBJ_APP_ID] = "ATTR_APP_ID";
		http_table_name_init(table_name);
		doq_table_name_init(table_name);
		mail_table_name_int(table_name);
		common_table_name_int(table_name);

		for (int i = 0; i < __TSG_OBJ_MAX; i++)
		{
			g_policy_rt->scan_table_id[i] = maat_get_table_id(g_policy_rt->feather[vsys_id], table_name[i]);
			if (g_policy_rt->scan_table_id[i] < 0)
			{
				log_fatal(g_policy_rt->local_logger, MODULE_VERIFY_MATCHER, "Maat table %s register failed.", table_name[i]);
				goto error_out;
			}
			log_debug(g_policy_rt->local_logger, MODULE_VERIFY_MATCHER, "Register maat %p, table name %s, table id %d", g_policy_rt->feather[vsys_id], table_name[i], g_policy_rt->scan_table_id[i]);
		}

		for(int i = 0; i < PXY_TABLE_DEFENCE; i++)
		{
			ret = maat_complie_plugin_table_init(vsys_id, i);
			if(ret<0)
			{
				goto error_out;
			}
		}

		for(int i = PROFILE_ASN_USER_DEFINED; i < PROFILE_FQDN_CAT_USER_DEFINED && g_policy_rt->load_ip_location; i++)
		{
			ret = maat_ip_table_init(i, vsys_id, ip_table_free_cb, ip_table_dup_cb);
			if(ret<0)
			{
				goto error_out;
			}
		}
		for(int i = PROFILE_FQDN_CAT_USER_DEFINED; i <= PROFILE_FQDN_CAT_BUILT_IN && g_policy_rt->load_fqdn_cat; i++)
		{
			ret = maat_plugin_table_ex_init(i, vsys_id, fqdn_cat_new_data, fqdn_cat_free_data, fqdn_cat_dup_data);
			if(ret<0)
			{
				goto error_out;
			}
		}
		for(int i=PROFILE_TUNNEL_CATALOG; i <=PROFILE_TUNNEL_LABEL; i++)
		{
			ret = maat_tunnel_table_init(i, vsys_id, tunnel_table_free_data, tunnel_table_dup_data);
			if(ret<0)
			{
				goto error_out;
			}
		}
		ret = maat_plugin_table_ex_init(PROFILE_APP_DI_DICT, vsys_id, app_dict_table_new_cb, app_dict_table_free_cb, app_dict_table_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}
	}
	ret = 0;
error_out:
	return ret;
}

