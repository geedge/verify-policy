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
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/stream.h>

#include <cjson/cJSON.h>

#include "verify_policy.h"
#include "verify_policy_utils.h"
#include "verify_policy_logging.h"

#define HIT_PATH_SIZE           	4096
#define	MAX_SCAN_RESULT				16

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
	POLICY_ASN_USER_DEFINED,
	POLICY_ASN_BUILT_IN,
	POLICY_LOCATION_USER_DEFINED,
	POLICY_LOCATION_BUILT_IN,
	POLICY_FQDN_CAT_USER_DEFINED,
	POLICY_FQDN_CAT_BUILT_IN,
	POLICY_TUNNEL_CATALOG,
	POLICY_TUNNEL_ENDPOINT,
	POLICY_TUNNEL_LABEL,
	POLICY_APP_DI_DICT,
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
	char *subdivision_addr;

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
	int Nth_scan[2];
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

	int req_hdr_num;
	int res_hdr_num;
	int tunnel_endpoint_x;
	int bool_id_array_idx;
    unsigned long long bool_id_array[256];

	struct ip_data_ctx ip_ctx;
	int thread_id;
};

struct verify_policy_rt
{
	struct maat *feather[VSYS_ID_MAX];
	void * local_logger;
	int log_level;
	int thread_num;
	int load_ip_location;
	int load_fqdn_cat;
	int hit_path_size;
	int compile_table_id[__SCAN_POLICY_MAX];
	int plugin_table_id[__SCAN_POLICY_MAX];
	int profile_table_id  [POLICY_PROFILE_TABLE_MAX];
	int scan_table_id[__TSG_OBJ_MAX];
};

static int ip_location_column_num =0;

struct verify_policy_rt * g_policy_rt;

#define MAAT_INPUT_JSON			0
#define MAAT_INPUT_REDIS    	1
#define MAAT_INPUT_FILE        	2

void verify_policy_tunnle_add(void * pme)
{
	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *) pme;
	ctx->tunnel_endpoint_x++;
}

void http_req_hdr_num(void *pem)
{
	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *)pem;
	ctx->req_hdr_num++;
}

void http_res_hdr_num(void *pem)
{
	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *)pem;
	ctx->res_hdr_num++;
}

void *policy_scan_ctx_new(unsigned int thread_id, int vsys_id, int compile_table_id)
{
	struct policy_scan_ctx * ctx = ALLOC(struct policy_scan_ctx, 1);
	ctx->scan_mid = maat_state_new(g_policy_rt->feather[vsys_id], thread_id);
	ctx->thread_id = (int) thread_id;
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
	int addr_type;
	int ret=0,profile_id=0,is_valid=0;
	char start_ip[40], end_ip[40],asn[40]={0};
	char organization[VERIFY_ARRAY_MAX];

	ret=sscanf(table_line, "%d\t%d\t%s\t%s\t%s\t%s\t%d", &profile_id, &addr_type, start_ip, end_ip, asn, organization, &is_valid);
	if(ret!=7)
	{
		mesa_runtime_log(RLOG_LV_FATAL, "Policy table parse ip ASN failed, ret:%d, %s", ret, table_line);
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

	mesa_runtime_log(RLOG_LV_DEBUG, "Policy table add success %d", profile_id);
	*ad = ip_asn;
}

static int get_column_num(const char* line)
{
	const char* seps=" \t";
	char* saveptr=NULL, *subtoken=NULL, *str=NULL;
	char* dup_line=strdup(line);
	int i=0;
	for (str = dup_line; ; str = NULL)
	{
		subtoken = strtok_r(str, seps, &saveptr);
		if (subtoken == NULL)
			break;
		i++;
	}
	free(dup_line);
	return i;
}

void ip_location_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0,profile_id=0,is_valid=0;
	int geoname_id=0, addr_type=0;
	double latitude, longitude, coords;
	char language[40], start_ip[40], end_ip[40];
	char continent_abbr[VERIFY_ARRAY_MAX],continent_full[VERIFY_ARRAY_MAX];
	char country_abbr[VERIFY_ARRAY_MAX],province_abbr[VERIFY_ARRAY_MAX], time_zone[VERIFY_ARRAY_MAX];
	char country_full[VERIFY_ARRAY_MAX],province_full[VERIFY_ARRAY_MAX], city_full[VERIFY_ARRAY_MAX];
	char subdivision_addr[VERIFY_STRING_MAX];

	if(ip_location_column_num == 0)
	{
		ip_location_column_num = get_column_num(table_line);
	}

	if(ip_location_column_num == 20)
	{
		ret=sscanf(table_line, "%d\t%d\t%d\t%s\t%s\t%lf\t%lf\t%lf\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d", &profile_id,&geoname_id,
			   &addr_type, start_ip,end_ip,&latitude,&longitude,&coords,language,
			   continent_abbr,continent_full, country_abbr,country_full,province_abbr,province_full,
			   city_full, time_zone,&is_valid);

		if(ret!=18)
		{
			mesa_runtime_log(RLOG_LV_FATAL, "Policy table parse ip location failed, ret:%d, %s", ret, table_line);
			return;
		}
	}
	else
	{
		ret=sscanf(table_line, "%d\t%d\t%d\t%s\t%s\t%lf\t%lf\t%lf\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d", &profile_id,&geoname_id,
			   &addr_type, start_ip,end_ip,&latitude,&longitude,&coords,language,
			   continent_abbr,continent_full, country_abbr,country_full,province_abbr,province_full,
			   city_full, subdivision_addr, time_zone,&is_valid);

		if(ret!=19)
		{
			mesa_runtime_log(RLOG_LV_FATAL, "Policy table parse ip location failed, ret:%d, %s", ret, table_line);
			return;
		}
	}

	verify_unescape(continent_full);
	verify_unescape(country_full);
	verify_unescape(province_full);
	verify_unescape(city_full);
	if(ip_location_column_num != 20)
	{
		verify_unescape(subdivision_addr);
	}
	struct ip_data_table* ip_asn=ALLOC(struct ip_data_table, 1);
	memset(ip_asn, 0, sizeof(struct ip_data_table));
	ip_asn->profile_id=profile_id;
	ip_asn->country_full=strdup(country_full);
	ip_asn->province_full=strdup(province_full);
	ip_asn->city_full=strdup(city_full);
	if(ip_location_column_num != 20)
	{
		ip_asn->subdivision_addr=strdup(subdivision_addr);
	}
	ip_asn->ref_cnt=1;
	pthread_mutex_init(&(ip_asn->lock), NULL);
	mesa_runtime_log(RLOG_LV_DEBUG, "Policy table add success %d", profile_id);

	*ad = ip_asn;
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
		mesa_runtime_log(RLOG_LV_FATAL, "Policy catalog table parse tunnel catalog failed, ret:%d, %s", ret, table_line);
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

	mesa_runtime_log(RLOG_LV_DEBUG, "Policy table add success %d", tunnel_id);
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
		mesa_runtime_log(RLOG_LV_FATAL, "Policy table parse tunnel end point failed, ret:%d, %s", ret, table_line);
		return;
	}

	struct tunnel_data_ctx* tunnel=ALLOC(struct tunnel_data_ctx, 1);
	memset(tunnel, 0, sizeof(struct tunnel_data_ctx));
	tunnel->id=endpoint_id;
	tunnel->description=strdup(description);
	tunnel->ref_cnt=1;
	pthread_mutex_init(&(tunnel->lock), NULL);

	mesa_runtime_log(RLOG_LV_DEBUG, "Policy endpoint table add success %d", endpoint_id);
	*ad = tunnel;
}

void tunnel_label_table_new_cb(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int ret=0,is_valid=0;
	int label_id=0;

	ret=sscanf(table_line, "%d\t%d", &label_id, &is_valid);
	if(ret!=2)
	{
		mesa_runtime_log(RLOG_LV_FATAL, "Policy table tunnel label failed, ret:%d, %s", ret, table_line);
		return;
	}

	struct tunnel_data_ctx* tunnel=ALLOC(struct tunnel_data_ctx, 1);
	memset(tunnel, 0, sizeof(struct tunnel_data_ctx));
	tunnel->id=label_id;
	tunnel->ref_cnt=1;
	pthread_mutex_init(&(tunnel->lock), NULL);

	mesa_runtime_log(RLOG_LV_DEBUG, "Policy label table add success %d", label_id);
	*ad = tunnel;
}


const char *table_name_map[] = {"TSG_IP_ASN_USER_DEFINED",
								"TSG_IP_ASN_BUILT_IN",
								"TSG_IP_LOCATION_USER_DEFINED",
								"TSG_IP_LOCATION_BUILT_IN",
								"TSG_FQDN_CATEGORY_USER_DEFINED",
								"TSG_FQDN_CATEGORY_BUILT_IN",
								"TSG_TUNNEL_CATALOG",
								"TSG_TUNNEL_ENDPOINT",
								"TSG_TUNNEL_LABEL"};

int maat_tunnel_table_init(int profile_idx,int vsys_id,
					   	   maat_ex_free_func_t* free_func,
					       maat_ex_dup_func_t* dup_func)
{
	int table_id=0;

	maat_ex_new_func_t *new_func[] = {
			[POLICY_ASN_USER_DEFINED] = NULL,
			[POLICY_ASN_BUILT_IN] = NULL,
			[POLICY_LOCATION_USER_DEFINED] = NULL,
			[POLICY_LOCATION_BUILT_IN] = NULL,
			[POLICY_FQDN_CAT_USER_DEFINED] = NULL,
			[POLICY_FQDN_CAT_BUILT_IN] = NULL,
			[POLICY_TUNNEL_CATALOG] = tunnel_catalog_table_new_cb,
			[POLICY_TUNNEL_ENDPOINT] = tunnel_endpoint_table_new_cb,
			[POLICY_TUNNEL_LABEL] = tunnel_label_table_new_cb
	};

	const char *table_name = table_name_map[profile_idx];
	table_id=g_policy_rt->profile_table_id[profile_idx]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id > 0)
	{
		table_id=maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, new_func[profile_idx], free_func, dup_func, 0, NULL);
		return table_id;
	}
	mesa_runtime_log(RLOG_LV_FATAL, "Register table %s failed.", table_name);
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

int maat_fqdn_cat_table_init(int profile_idx, int vsys_id,
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
	mesa_runtime_log(RLOG_LV_FATAL, "Register fqdn cat table %s failed.", table_name);
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

int maat_app_dict_table_init(int profile_idx, int vsys_id,
							 	maat_ex_new_func_t* new_func,
							 	maat_ex_free_func_t* free_func,
							 	maat_ex_dup_func_t* dup_func)
{
	int table_id=0, ret=0;

	const char *table_name = "APP_ID_DICT";
	table_id=g_policy_rt->profile_table_id[profile_idx]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id >= 0)
	{
		ret=maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, new_func, free_func, dup_func,
										0, NULL);
		return ret;
	}
	mesa_runtime_log(RLOG_LV_FATAL, "Register app dict table %s failed.", table_name);
	return -1;
}

int maat_ip_table_init(int profile_idx,int vsys_id,
					   maat_ex_free_func_t* free_func,
					   maat_ex_dup_func_t* dup_func)
{
	int table_id=0;

	maat_ex_new_func_t *new_func[] = {
			[POLICY_ASN_USER_DEFINED] = ip_asn_table_new_cb,
			[POLICY_ASN_BUILT_IN] = ip_asn_table_new_cb,
			[POLICY_LOCATION_USER_DEFINED] = ip_location_table_new_cb,
			[POLICY_LOCATION_BUILT_IN] = ip_location_table_new_cb,
	};

	const char *table_name = table_name_map[profile_idx];
	table_id=g_policy_rt->profile_table_id[profile_idx]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id >= 0)
	{
		table_id=maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, new_func[profile_idx], free_func, dup_func,
									   0, NULL);
		return 0;
	}
	mesa_runtime_log(RLOG_LV_FATAL, "Register table %s failed.", table_name);
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
		mesa_runtime_log(RLOG_LV_FATAL, "Parse fqdn category failed, ret: %d table_id: %d table_line: %s", ret, table_id, table_line);
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
		mesa_runtime_log(RLOG_LV_FATAL, "Security compile table parse failed, ret:%d, %s", ret, table_line);
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
	if(table_id==TSG_OBJ_HTTP_HOST || table_id==TSG_OBJ_SSL_SNI || table_id==TSG_OBJ_SSL_CN || table_id==TSG_OBJ_SSL_SAN
	   || table_id==TSG_OBJ_DNS_QNAME || table_id==TSG_OBJ_QUIC_SNI || table_id==TSG_OBJ_DOH_QNAME || table_id==TSG_OBJ_DOH_HOST
	   || table_id==TSG_OBJ_DST_SERVER_FQDN)
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
		item = cJSON_GetObjectItem(attributeObj, "attributeName");
		if(item && item->type==cJSON_String)
		{
			if(0 == strcasecmp(item->valuestring, "tunnel_endpointa"))
			{
				return;
			}
		}
	}

	if(compile_table_id == TSG_TABLE_SECURITY && query_obj->table_id == TSG_OBJ_TUNNEL)
	{
		attributeObj=query_obj->attributes;
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

int get_attributes_table_name(struct request_query_obj *query_obj, int num, int Nth_scan, struct ip_data_ctx *ip_ctx, int tunnel_endpoint_x, cJSON *topObject)
{
	int i=0, j=0;
	cJSON *attributeObj=NULL, *subchild=NULL;

	/*ip location**/
	if(ip_ctx->Nth_scan[0] == Nth_scan)
	{
		cJSON_AddStringToObject(topObject, "tableName", "ATTR_SOURCE_ADDR");
		return 0;
	}

	if(ip_ctx->Nth_scan[1] == Nth_scan)
	{
		cJSON_AddStringToObject(topObject, "tableName", "ATTR_DESTINATION_ADDR");
		return 0;
	}

	for(i=0; i<num; i++)
	{
		for(j=0; j<= query_obj[i].merge_nth_scan_num; j++)
		{
			if (query_obj[i].merge_nth_scan[j] == Nth_scan)
			{
				attributeObj=query_obj[i].attributes;
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

			topObjectList=cJSON_CreateArray();
			cJSON_AddItemToObject(policy_obj, "topObjectList", topObjectList);
			for(j=0; j<=(size_t)ctx->n_read; j++)
			{
				if(ctx->hit_path[j].compile_id > 0 && ctx->hit_path[j].compile_id == ctx->hit_rules[i].config_id)
				{
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

int ip_location_scan(long long *result, struct ip_addr *sip, struct ip_addr *dip, int hit_cnt, unsigned int thread_id, int vsys_id, struct policy_scan_ctx *ctx)
{
	size_t n_hit_result=0;
	int scan_ret=0, hit_cnt_ip=0;
	char buff[VERIFY_STRING_MAX * 2]={0};
	struct maat_hit_path hit_path[HIT_PATH_SIZE];
	struct ip_data_table* ip_location_client=NULL, *ip_location_server=NULL;

	if(!g_policy_rt->load_ip_location)
	{
		return 0;
	}

	memset(hit_path, 0, sizeof(struct maat_hit_path)*HIT_PATH_SIZE);
	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_LOCATION_USER_DEFINED], sip, (void **)&ip_location_client, 1);
	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_LOCATION_USER_DEFINED], dip, (void **)&ip_location_server, 1);

	if (ip_location_client == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_LOCATION_BUILT_IN], sip,(void **)&ip_location_client, 1);
	}
	if (ip_location_server == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_LOCATION_BUILT_IN], dip, (void **)&ip_location_server, 1);
	}

	if(ip_location_server!=NULL)
	{
		memset(buff,0,sizeof(buff));
		if(ip_location_server->subdivision_addr == NULL || strcasecmp(ip_location_server->subdivision_addr, "null") == 0)
		{
			snprintf(buff, sizeof(buff), "%s.%s.%s", ip_location_server->country_full, ip_location_server->province_full, ip_location_server->city_full);
		}
		else
		{
			snprintf(buff, sizeof(buff), "%s.%s.%s.%s", ip_location_server->country_full, ip_location_server->province_full, ip_location_server->city_full, ip_location_server->subdivision_addr);
		}
		ctx->ip_ctx.location_server=strdup(buff);

		memset(buff,0,sizeof(buff));

		if(ip_location_server->subdivision_addr == NULL)
		{
			snprintf(buff, sizeof(buff), "%s.%s.", ip_location_server->country_full, ip_location_server->city_full);
		}
		else
		{
			snprintf(buff, sizeof(buff),"%s.%s.%s.%s.", ip_location_server->country_full,ip_location_server->province_full, ip_location_server->city_full, ip_location_server->subdivision_addr);
		}
		scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_DST_LOCATION],
									buff, strlen(buff), result+hit_cnt+hit_cnt_ip,  MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
									&n_hit_result, ctx->scan_mid);
		if(scan_ret>0)
		{
			hit_cnt_ip+=n_hit_result;
		}
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_DST_LOCATION], result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		if(scan_ret >= MAAT_SCAN_OK)
		{
			ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);
			ctx->ip_ctx.Nth_scan[1] = maat_state_get_scan_count(ctx->scan_mid);
		}
	}
	if(ip_location_client!=NULL)
	{
		memset(buff,0,sizeof(buff));
		if(ip_location_client->subdivision_addr == NULL || strcasecmp(ip_location_client->subdivision_addr, "null") == 0)
		{
			snprintf(buff, sizeof(buff), "%s.%s.%s", ip_location_client->country_full, ip_location_client->province_full, ip_location_client->city_full);
		}
		else
		{
			snprintf(buff, sizeof(buff), "%s.%s.%s.%s", ip_location_client->country_full, ip_location_client->province_full, ip_location_client->city_full, ip_location_client->subdivision_addr);
		}

		ctx->ip_ctx.location_client=strdup(buff);

		memset(buff,0,sizeof(buff));
		if(ip_location_client->subdivision_addr == NULL)
		{
			snprintf(buff, sizeof(buff), "%s.%s.", ip_location_client->country_full, ip_location_client->city_full);
		}
		else
		{
			snprintf(buff, sizeof(buff),"%s.%s.%s.%s.", ip_location_client->country_full,ip_location_client->province_full, ip_location_client->city_full, ip_location_client->subdivision_addr);
		}
		scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_SRC_LOCATION],
									buff, strlen(buff),result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
									&n_hit_result, ctx->scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_SRC_LOCATION], result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		if(scan_ret >= MAAT_SCAN_OK)
		{
			ctx->n_read=maat_state_get_hit_paths(ctx->scan_mid, hit_path, HIT_PATH_SIZE);
			ctx->ip_ctx.Nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
		}
	}

	if(ip_location_server)
		ip_table_free(ip_location_server);
	if(ip_location_client)
		ip_table_free(ip_location_client);
	return hit_cnt_ip;
}

int ip_asn_scan(long long *result, struct ip_addr* sip, struct ip_addr* dip, int hit_cnt, unsigned int thread_id, int vsys_id, struct policy_scan_ctx * ctx)
{
	size_t n_hit_result=0;
	int scan_ret=0, hit_cnt_ip=0;
	struct ip_data_table* ip_asn_client=NULL, *ip_asn_server=NULL;

	if(!g_policy_rt->load_ip_location)
	{
		return 0;
	}

	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_ASN_USER_DEFINED], sip, (void **)&ip_asn_client, 1);
	maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_ASN_USER_DEFINED], dip, (void **)&ip_asn_server, 1);

	if (ip_asn_client == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_ASN_BUILT_IN], sip,(void **)&ip_asn_client, 1);
	}
	if (ip_asn_server == NULL)
	{
		maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_ASN_BUILT_IN], dip,(void **)&ip_asn_server, 1);
	}

	if(ip_asn_server!=NULL)
	{
		ctx->ip_ctx.asn_server=strdup(ip_asn_server->asn);
		ctx->ip_ctx.organization_server=strdup(ip_asn_server->organization);

		scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_DST_ASN],
								    ip_asn_server->asn, strlen(ip_asn_server->asn),
								    result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
								    &n_hit_result, ctx->scan_mid);

		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_DST_ASN], result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
	}
	if(ip_asn_client!=NULL)
	{
		ctx->ip_ctx.asn_client=strdup(ip_asn_client->asn);
		ctx->ip_ctx.organization_client=strdup(ip_asn_client->organization);

		scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_SRC_ASN],
								   ip_asn_client->asn, strlen(ip_asn_client->asn),
								   result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
								   &n_hit_result, ctx->scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_IP_SRC_ASN], result+hit_cnt+hit_cnt_ip, MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,
                          			  &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_ip+=n_hit_result;
		}
	}
	if(ip_asn_server)
		ip_table_free(ip_asn_server);
	if(ip_asn_client)
		ip_table_free(ip_asn_client);
	return hit_cnt_ip;
}

int get_fqdn_category_id(long long *result, const char *fqdn, int table_id, int hit_cnt, unsigned int thread_id, int vsys_id, struct policy_scan_ctx * ctx, struct request_query_obj *query_obj)
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

	ret=maat_fqdn_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_FQDN_CAT_USER_DEFINED], fqdn, (void **)fqdn_cat_user, 8);
	for(i=0; i <ret; i++)
	{
		if(i < 8)
		{
			if(http_hit_policy_match((int *)(query_obj->fqdn_user.group_id), j, (int)fqdn_cat_user[i]->group_id))
			{
				continue;
			}
			query_obj->fqdn_user.group_id[j] = fqdn_cat_user[i]->group_id;
			j++;
		}
		fqdn_cat_table_free(fqdn_cat_user[i]);
	}
	query_obj->fqdn_user.fqdn_cat_num = j< 8 ? j : 8;

	ret=maat_fqdn_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_FQDN_CAT_BUILT_IN], fqdn, (void **)fqdn_cat_built, 8);
	for(i=0; i <ret; i++)
	{
		if(i < 8)
		{
			if(http_hit_policy_match((int *)(query_obj->fqdn_builtin.group_id), k, (int)fqdn_cat_built[i]->group_id))
			{
				continue;
			}
			query_obj->fqdn_builtin.group_id[k] = fqdn_cat_built[i]->group_id;
			k++;
		}
		fqdn_cat_table_free(fqdn_cat_built[i]);
	}
	query_obj->fqdn_builtin.fqdn_cat_num  = k < 8 ? k : 8;

	if(query_obj->fqdn_user.fqdn_cat_num > 0)
	{
		for(i=0; i<query_obj->fqdn_user.fqdn_cat_num; i++)
		{
	    	ret=maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &query_obj->fqdn_user.group_id[i], 1,
							    result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if(ret == MAAT_SCAN_HIT)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								  	  result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if (ret == MAAT_SCAN_HIT)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			if(ret >= MAAT_SCAN_OK)
			{
				query_obj->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);;
				query_obj->exclude_nth_scan[hit_path_cnt] = 1;
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
		goto finish;
	}
	if (query_obj->fqdn_builtin.fqdn_cat_num > 0)
	{
		for(i=0; i<query_obj->fqdn_builtin.fqdn_cat_num; i++)
		{
			ret=maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &query_obj->fqdn_builtin.group_id[i], 1,
							    result+hit_cnt+hit_cnt_fqdn, MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if(ret>0)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], result+hit_cnt+hit_cnt_fqdn,
								      MAX_SCAN_RESULT-hit_cnt-hit_cnt_fqdn, &n_hit_result, ctx->scan_mid);
			if (ret == MAAT_SCAN_HIT)
			{
				hit_cnt_fqdn+=n_hit_result;
			}
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			if(ret >= MAAT_SCAN_OK)
			{
				query_obj->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);
				query_obj->exclude_nth_scan[hit_path_cnt] = 1;
				ctx->n_read=n_read;
				hit_path_cnt++;
			}
		}
	}
finish:
	query_obj->merge_nth_scan_num = hit_path_cnt;
	return hit_cnt_fqdn;
}

int policy_verify_scan_tunnel(long long *result, struct ip_addr *sip, int hit_cnt, unsigned int thread_id, int vsys_id, struct policy_scan_ctx * ctx, struct request_query_obj *query_obj)
{
#define	TUNNEL_BOOL_ID_MAX	128
#define	TUNNEL_CATALOG_MAX	128

	size_t n_hit_result=0;
	int i=0,ret=0,n_read=0;
	int scan_ret=0, hit_cnt_tunnel=0;
	int hit_path_cnt=0;
	struct tunnel_data_ctx *endpoint_data[TUNNEL_BOOL_ID_MAX];

	ret=maat_ip_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_TUNNEL_ENDPOINT], sip, (void **)&endpoint_data, TUNNEL_BOOL_ID_MAX);
	for(i=0; i<ret && i<TUNNEL_BOOL_ID_MAX; i++)
	{
		ctx->bool_id_array[ctx->bool_id_array_idx]=(long long)endpoint_data[i]->id;
		ctx->bool_id_array_idx++;
		tunnel_table_free(endpoint_data[i]);
	}

	struct tunnel_data_ctx *tunnel_catalog[TUNNEL_CATALOG_MAX];
	ret=maat_bool_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_TUNNEL_CATALOG], ctx->bool_id_array, ctx->bool_id_array_idx, (void**)(&tunnel_catalog), TUNNEL_CATALOG_MAX);
	for(i=0; i<ret && i<TUNNEL_CATALOG_MAX; i++)
	{
		scan_ret=maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_TUNNEL], &tunnel_catalog[i]->group_id, 1,
							    result+hit_cnt+hit_cnt_tunnel, MAX_SCAN_RESULT-hit_cnt-hit_cnt_tunnel, &n_hit_result, ctx->scan_mid);
		if(scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_tunnel+=n_hit_result;
		}
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[TSG_OBJ_TUNNEL],result+hit_cnt+hit_cnt_tunnel, MAX_SCAN_RESULT-hit_cnt-hit_cnt_tunnel,
                          			   &n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_tunnel+=n_hit_result;
		}
		if(scan_ret >= MAAT_SCAN_OK)
		{
			n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
			query_obj->merge_nth_scan[hit_path_cnt] = maat_state_get_scan_count(ctx->scan_mid);
			ctx->n_read=n_read;
			hit_path_cnt++;
		}
		tunnel_table_free(tunnel_catalog[i]);
	}
	query_obj->merge_nth_scan_num = hit_path_cnt;
	return hit_cnt_tunnel;
}

static int policy_verify_scan_app_id(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_app_id=0;
	struct app_id_dict *app_dict=NULL;
	size_t n_hit_result=0;

	long long app_id = request->numeric;
	int table_id = request->table_id;

	app_dict = (struct app_id_dict*)maat_plugin_table_get_ex_data(g_policy_rt->feather[vsys_id], g_policy_rt->profile_table_id[POLICY_APP_DI_DICT], (const char *)&app_id, sizeof(long long));
	if(app_dict==NULL)
	{
		return 0;
	}

    scan_ret = maat_scan_group(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], &app_dict->group_id, 1,
							   ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt, &n_hit_result, ctx->scan_mid);
	if(scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_app_id+=n_hit_result;
	}
	scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt,
									&n_hit_result, ctx->scan_mid);
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

static int policy_verify_scan_flag(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
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

static int policy_verify_scan_http_hdr(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt, int hdr_num)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_hdr=0;
	size_t n_hit_result=0;

	if(!request->district || !request->keyword)
	{
		return hit_cnt_hdr;
	}

	int table_id = request->table_id;
	const char *value = request->keyword;
	const char * str_field_name = request->district;
	maat_state_set_scan_district(ctx->scan_mid, g_policy_rt->scan_table_id[table_id], str_field_name, strlen(str_field_name));
	scan_ret = maat_scan_string(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								value, strlen(value), ctx->result + hit_cnt, MAX_SCAN_RESULT - hit_cnt,
		 					    &n_hit_result, ctx->scan_mid);
	if (scan_ret == MAAT_SCAN_HIT)
	{
		hit_cnt_hdr += n_hit_result;
	}

	if(hdr_num == 0)
	{
		scan_ret = maat_scan_not_logic(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id], ctx->result + hit_cnt, MAX_SCAN_RESULT - hit_cnt,
                          				&n_hit_result, ctx->scan_mid);
		if (scan_ret == MAAT_SCAN_HIT)
		{
			hit_cnt_hdr += n_hit_result;
		}
	}
	n_read=maat_state_get_hit_paths(ctx->scan_mid, ctx->hit_path, HIT_PATH_SIZE);
	request->merge_nth_scan[0] = maat_state_get_scan_count(ctx->scan_mid);
	ctx->n_read=n_read;
	return hit_cnt_hdr;
}

static int ip_addr_scan(struct request_query_obj *request, struct policy_scan_ctx *ctx, int vsys_id, int hit_cnt)
{
	int n_read=0;
	int scan_ret=0, hit_cnt_ip=0;
	size_t n_hit_result=0;

	int table_id = request->table_id;
	int protocol = request->protocol;
	if (request->ip_addr->addrtype == ADDR_TYPE_IPV4)
	{
		if(0 == strcasecmp(request->attri_name, "source") || 0 == strcasecmp(request->attri_name, "internal"))
		{
			scan_ret = maat_scan_ipv4(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								      request->ip_addr->v4->saddr, request->ip_addr->v4->source, protocol, ctx->result+hit_cnt+hit_cnt_ip,
								      MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip,&n_hit_result, ctx->scan_mid);
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
			scan_ret = maat_scan_ipv4(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								      request->ip_addr->v4->daddr, request->ip_addr->v4->dest, protocol,ctx->result+hit_cnt+hit_cnt_ip,
								      MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);

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
			scan_ret = maat_scan_ipv6(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								      request->ip_addr->v6->saddr, request->ip_addr->v6->source, protocol,ctx->result+hit_cnt+hit_cnt_ip,
								      MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
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
			scan_ret = maat_scan_ipv6(g_policy_rt->feather[vsys_id], g_policy_rt->scan_table_id[table_id],
								     request->ip_addr->v6->daddr, request->ip_addr->v6->dest, protocol, ctx->result+hit_cnt+hit_cnt_ip,
								     MAX_SCAN_RESULT-hit_cnt-hit_cnt_ip, &n_hit_result, ctx->scan_mid);
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

size_t policy_verify_scan(int vsys_id, int compile_table_id, struct request_query_obj *request, void *pme)
{
	size_t n_hit_result=0;
	int scan_ret=0, n_read;

	struct policy_scan_ctx * ctx = (struct policy_scan_ctx *) pme;
	size_t hit_cnt = ctx->hit_cnt;

	int table_id = request->table_id;
	const char *value = request->keyword;

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

			scan_ret = ip_location_scan(ctx->result, &source_ip, &dest_ip, hit_cnt, ctx->thread_id, vsys_id, ctx);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			scan_ret = ip_asn_scan(ctx->result, &source_ip, &dest_ip, hit_cnt, ctx->thread_id, vsys_id, ctx);
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
		case TSG_OBJ_TUNNEL:
			memset(&dest_ip, 0, sizeof(dest_ip));
			memset(&source_ip, 0, sizeof(source_ip));
			ip_addr_to_address(request->ip_addr, &dest_ip, &source_ip);
			scan_ret = policy_verify_scan_tunnel(ctx->result, &source_ip, hit_cnt, ctx->thread_id, vsys_id,  ctx, request);
			if(scan_ret)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_APP_ID:
			scan_ret = policy_verify_scan_app_id(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_FLAG:
			scan_ret = policy_verify_scan_flag(request, ctx, vsys_id, hit_cnt);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_HTTP_REQ_HDR:
			ctx->req_hdr_num--;
			scan_ret = policy_verify_scan_http_hdr(request, ctx, vsys_id, hit_cnt, ctx->req_hdr_num);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		case TSG_OBJ_HTTP_RES_HDR:
			ctx->res_hdr_num--;
			scan_ret = policy_verify_scan_http_hdr(request, ctx, vsys_id, hit_cnt, ctx->res_hdr_num);
			if(scan_ret > 0)
			{
				hit_cnt+=scan_ret;
			}
			goto decide;
		default:
			break;
	}

	if(request_in_fqdn_cat(table_id))
	{
		/*TSG_HOST, TSG_HOST+1=TSG_HOST_CAT**/
		scan_ret = get_fqdn_category_id(ctx->result, value, table_id+1, hit_cnt, ctx->thread_id, vsys_id, ctx, request);
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
		mesa_runtime_log(RLOG_LV_FATAL, "Invalid redis port range %s, MAAT init failed.", redis_port_range);
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
		default: mesa_runtime_log(RLOG_LV_FATAL, "Invalid MAAT Input Mode: %d.", input_mode);
			goto error_out;
			break;
	}
	maat_options_set_foreign_cont_dir(opts, "./verify_policy_files");
	maat_options_set_rule_effect_interval_ms(opts, effect_interval);
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
		mesa_runtime_log(RLOG_LV_FATAL, "%s MAAT init failed.", __FUNCTION__);
		goto error_out;
	}

	mesa_runtime_log(RLOG_LV_INFO, "%s:%s", "Maat Redis Ip", redis_ip);
	mesa_runtime_log(RLOG_LV_INFO, "%s:%s", "Maat Redis Port", redis_port_range);
	mesa_runtime_log(RLOG_LV_INFO, "%s:%d", "Maat Redis_db_index", db_index);

    maat_options_free(opts);
	return target;

error_out:
    maat_options_free(opts);
	return NULL;
}

static void http_table_name_init(const char *table_name[__TSG_OBJ_MAX])
{
	table_name[TSG_OBJ_HTTP_URL] = "ATTR_HTTP_URL";
	table_name[TSG_OBJ_HTTP_HOST] =  "ATTR_HTTP_HOST";
	table_name[TSG_OBJ_HTTP_HOST_CAT] = "ATTR_HTTP_HOST_CAT";
	table_name[TSG_OBJ_HTTP_REQ_HDR] =  "ATTR_HTTP_REQ_HDR";
	table_name[TSG_OBJ_HTTP_REQ_BODY] =  "ATTR_HTTP_REQ_BODY";
	table_name[TSG_OBJ_HTTP_RES_HDR] =  "ATTR_HTTP_RES_HDR";
	table_name[TSG_OBJ_HTTP_RES_BODY] = "ATTR_HTTP_RES_BODY";
	table_name[TSG_OBJ_SSL_SNI] =  "ATTR_SSL_SNI";
	table_name[TSG_OBJ_SSL_SNI_CAT] = "ATTR_SSL_SNI_CAT";
	table_name[TSG_OBJ_SSL_CN] =  "ATTR_SSL_CN";
	table_name[TSG_OBJ_SSL_CN_CAT] = "ATTR_SSL_CN_CAT";
	table_name[TSG_OBJ_SSL_SAN] = "ATTR_SSL_SAN";
	table_name[TSG_OBJ_SSL_SAN_CAT] = "ATTR_SSL_SAN_CAT";
	return;
}

static void doq_table_name_init(const char *table_name[__TSG_OBJ_MAX])
{
	table_name[TSG_OBJ_DNS_QNAME]="ATTR_DNS_QNAME";
	table_name[TSG_OBJ_DOH_HOST]="ATTR_DOH_HOST";
	table_name[TSG_OBJ_DOH_HOST_CAT]="ATTR_DOH_HOST_CAT";
	table_name[TSG_OBJ_DOH_QNAME] = "ATTR_DOH_QNAME";
	table_name[TSG_OBJ_QUIC_SNI] = "ATTR_QUIC_SNI";
	table_name[TSG_OBJ_QUIC_SNI_CAT] = "ATTR_QUIC_SNI_CAT";
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
	table_name[TSG_OBJ_IP_SRC_LOCATION]="ATTR_SOURCE_LOCATION";
	table_name[TSG_OBJ_IP_DST_LOCATION]="ATTR_DESTINATION_LOCATION";
	table_name[TSG_OBJ_DST_SERVER_FQDN]="ATTR_SERVER_FQDN";
	table_name[TSG_OBJ_DST_SERVER_FQDN_CAT]="ATTR_SERVER_FQDN_CAT";
	table_name[TSG_OBJ_INTERNAL_ADDR]="ATTR_INTERNAL_ADDR";
	table_name[TSG_OBJ_EXTERNAL_ADDR]="ATTR_EXTERNAL_ADDR";
	return;
}

int maat_complie_plugin_table_init(int vsys_id, int compile_type_id)
{
	int table_id=0;
	const char *table_name=NULL;

	const char *conjunction_table_name_map[] = {"TSG_SECURITY_COMPILE_CONJUNCTION", "PXY_CTRL_COMPILE_CONJUNCTION", "TRAFFIC_SHAPING_COMPILE_CONJUNCTION",
												"SERVICE_CHAINING_COMPILE_CONJUNCTION", "PXY_INTERCEPT_COMPILE_CONJUNCTION","STATISTICS_COMPILE_CONJUNCTION", "MONITOR_COMPILE_CONJUNCTION"};

	table_name = conjunction_table_name_map[compile_type_id];
	table_id=g_policy_rt->compile_table_id[compile_type_id]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id < 0)
	{
		return table_id;
	}

	const char *plugin_table_name_map[] = {"TSG_SECURITY_COMPILE_PLUGIN", "PXY_CTRL_COMPILE_PLUGIN", "TRAFFIC_SHAPING_COMPILE_PLUGIN",
											"SERVICE_CHAINING_COMPILE_PLUGIN", "PXY_INTERCEPT_COMPILE_PLUGIN", "STATISTICS_COMPILE_PLUGIN", "MONITOR_COMPILE_PLUGIN"};

	table_name = plugin_table_name_map[compile_type_id];
	table_id = g_policy_rt->plugin_table_id[compile_type_id]=maat_get_table_id(g_policy_rt->feather[vsys_id], table_name);
	if(table_id >=0 )
	{
		maat_plugin_table_ex_schema_register(g_policy_rt->feather[vsys_id], table_name, compile_table_new_cb, compile_free_data, compile_dup_data, 0,NULL);
	}
	return table_id;
}

int maat_table_init(struct verify_policy * verify, const char* profile_path)
{
	int ret = -1; int vsys_id=0;
	int load_vsys_num=0;
	char log_path[VERIFY_PATH_MAX];

	snprintf(log_path, sizeof(log_path), "logs/maat.log");
	g_policy_rt = ALLOC(struct verify_policy_rt, 1);
	g_policy_rt->local_logger = verify->logger;
	g_policy_rt->thread_num = verify->nr_work_threads;

	MESA_load_profile_int_def(profile_path, "MAAT", "load_ip_location", &(g_policy_rt->load_ip_location), 1);
	MESA_load_profile_int_def(profile_path, "MAAT", "load_fqdn_cat", &(g_policy_rt->load_fqdn_cat), 1);
	MESA_load_profile_int_def(profile_path, "MAAT", "load_vsys_num", &(load_vsys_num), 255);
	load_vsys_num = load_vsys_num > VSYS_ID_MAX ? VSYS_ID_MAX : load_vsys_num;

	for(vsys_id=0; vsys_id < load_vsys_num; vsys_id++)
	{
		g_policy_rt->feather[vsys_id] = create_maat_feather("static", profile_path, "MAAT", g_policy_rt->thread_num, log_path, vsys_id);
		if (!g_policy_rt->feather[vsys_id])
		{
			goto error_out;
		}
		const char * table_name[__TSG_OBJ_MAX];
		table_name[TSG_OBJ_SOURCE_ADDR] = "ATTR_SOURCE_ADDR";
		table_name[TSG_OBJ_DESTINATION_ADDR]="ATTR_DESTINATION_ADDR";
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
				mesa_runtime_log(RLOG_LV_FATAL, "Maat table %s register failed.", table_name[i]);
				goto error_out;
			}
			mesa_runtime_log(RLOG_LV_DEBUG, "Register maat %p, table name %s, table id %d", g_policy_rt->feather[vsys_id], table_name[i], g_policy_rt->scan_table_id[i]);
		}

		for(int i = 0; i < PXY_TABLE_DEFENCE; i++)
		{
			ret = maat_complie_plugin_table_init(vsys_id, i);
			if(ret<0)
			{
				goto error_out;
			}
		}

		for(int i = POLICY_ASN_USER_DEFINED; i < POLICY_FQDN_CAT_USER_DEFINED && g_policy_rt->load_ip_location; i++)
		{
			ret = maat_ip_table_init(i, vsys_id, ip_table_free_cb, ip_table_dup_cb);
			if(ret<0)
			{
				goto error_out;
			}
		}
		for(int i = POLICY_FQDN_CAT_USER_DEFINED; i <= POLICY_FQDN_CAT_BUILT_IN && g_policy_rt->load_fqdn_cat; i++)
		{
			ret = maat_fqdn_cat_table_init(i, vsys_id, fqdn_cat_new_data, fqdn_cat_free_data, fqdn_cat_dup_data);
			if(ret<0)
			{
				goto error_out;
			}
		}
		for(int i=POLICY_TUNNEL_CATALOG; i <=POLICY_TUNNEL_LABEL; i++)
		{
			ret = maat_tunnel_table_init(i, vsys_id, tunnel_table_free_data, tunnel_table_dup_data);
			if(ret<0)
			{
				goto error_out;
			}
		}
		ret = maat_app_dict_table_init(POLICY_APP_DI_DICT, vsys_id, app_dict_table_new_cb, app_dict_table_free_cb, app_dict_table_dup_cb);
		if(ret<0)
		{
			goto error_out;
		}
	}
	ret = 0;
error_out:
	return ret;
}

