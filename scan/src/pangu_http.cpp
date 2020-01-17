/*************************************************************************
	> File Name: pangu_http.cpp
	> Author:
	> Mail:
	> Created Time: 2019年08月23日 星期五 16时53分25秒
 ************************************************************************/
#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <MESA/Maat_rule.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/stream.h>

#include <cjson/cJSON.h>

#include "verify_policy.h"
#include "verify_policy_utils.h"
#include "verify_policy_logging.h"

#define	MAX_SCAN_RESULT				16

enum pangu_action //Bigger action number is prior.
{
	PG_ACTION_NONE = 0x00,
	PG_ACTION_MONIT = 0x01,
	PG_ACTION_FORWARD = 0x02,    /* N/A */
	PG_ACTION_REJECT = 0x10,
	PG_ACTION_DROP = 0x20,    /* N/A */
	PG_ACTION_MANIPULATE = 0x30,
	PG_ACTION_RATELIMIT = 0x40,    /* N/A */
	PG_ACTION_LOOP = 0x60,    /* N/A */
	PG_ACTION_WHITELIST = 0x80,
	__PG_ACTION_MAX
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

static int pangu_action_weight[__PG_ACTION_MAX] = {0};
void __pangu_action_weight_init()  __attribute__((constructor, used));
void __pangu_action_weight_init()
{
	pangu_action_weight[PG_ACTION_NONE] = 0;
	pangu_action_weight[PG_ACTION_MONIT] = 1;
	pangu_action_weight[PG_ACTION_MANIPULATE] = 2;
	pangu_action_weight[PG_ACTION_REJECT] = 3;
	pangu_action_weight[PG_ACTION_WHITELIST] = 4;
}

static inline int action_cmp(enum pangu_action a1, enum pangu_action a2)
{
	return pangu_action_weight[a1] - pangu_action_weight[a2];
}

static enum pangu_action decide_ctrl_action(const struct Maat_rule_t * hit_rules, size_t n_hit,
	struct Maat_rule_t ** enforce_rules, size_t * n_enforce)
{
	size_t n_monit = 0, exist_enforce_num = 0, i = 0;
	const struct Maat_rule_t * prior_rule = hit_rules;
	struct Maat_rule_t monit_rule[n_hit];
	enum pangu_action prior_action = PG_ACTION_NONE;

	for (i = 0; i < n_hit; i++)
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

char *web_json_table_add(void *pme)
{
	char *policy_payload = NULL; size_t i = 0;
	cJSON  *policy_obj=NULL, *data_obj=NULL, *hit_obj=NULL;
	cJSON  *execute_obj=NULL, *obj_list=NULL, *category_obj=NULL;

	struct pangu_http_ctx * ctx = (struct pangu_http_ctx *) pme;

	policy_obj=cJSON_CreateObject();
	cJSON_AddNumberToObject(policy_obj, "code", 200);
	cJSON_AddStringToObject(policy_obj, "msg", "Success");
	cJSON_AddNumberToObject(policy_obj, "success", 1);

	data_obj = cJSON_CreateObject();
	cJSON_AddItemToObject(policy_obj, "data", data_obj);

	/*hitPolicyList **/
	hit_obj = cJSON_CreateObject();
	cJSON_AddItemToObject(data_obj, "hitPolicyList", hit_obj);
	if (ctx->hit_cnt >= 1)
	{
		for (i = 0; i < ctx->hit_cnt; i++)
		{
			cJSON_AddNumberToObject(hit_obj, "policyId", ctx->result[i].config_id);
			cJSON_AddStringToObject(hit_obj, "policyName", "");
		}
	}
	/*executePolicyList **/
	execute_obj = cJSON_CreateObject();
	cJSON_AddItemToObject(data_obj, "executePolicyList", execute_obj);
	cJSON_AddNumberToObject(execute_obj, "policyId", ctx->enforce_rules[0].config_id);
	cJSON_AddStringToObject(execute_obj, "policyName", "");

	/*objectList**/
	obj_list = cJSON_CreateObject();
	cJSON_AddItemToObject(data_obj, "objectList", obj_list);
	cJSON_AddNumberToObject(obj_list, "objectId", 12);
	cJSON_AddStringToObject(obj_list, "objectName", "");
	cJSON *itemList = cJSON_CreateObject();
	cJSON_AddItemToObject(obj_list, "itemList", itemList);
	cJSON_AddNumberToObject(itemList, "itemId", 12);
	cJSON_AddStringToObject(itemList, "reqParam", "");

	/*categoryList**/
	category_obj = cJSON_CreateObject();
	cJSON_AddItemToObject(data_obj, "categoryList", category_obj);
	cJSON_AddNumberToObject(category_obj, "categoryId", 12);
	cJSON_AddStringToObject(category_obj, "reqParam", "");

	policy_payload = cJSON_PrintUnformatted(policy_obj);
	printf("%s\n", policy_payload);
	cJSON_Delete(policy_obj);

	return policy_payload;
}

void http_scan(const char * value, enum policy_type type, int protocol_field, void *pme, cJSON *data_obj, struct ipaddr *ip_addr)
{
	int scan_ret = 0, table_id = 0;
	struct Maat_rule_t result[MAX_SCAN_RESULT];
	char buff[VERIFY_STRING_MAX], * p = NULL;
	size_t hit_cnt = 0, i = 0;

	struct pangu_http_ctx * ctx = (struct pangu_http_ctx *) pme;

	if (protocol_field == PXY_CTRL_IP)
	{
		scan_ret = Maat_scan_proto_addr(g_pangu_rt->maat[type], g_pangu_rt->scan_table_id[type][protocol_field], ip_addr, 0,
				   ctx->result+hit_cnt, MAX_SCAN_RESULT-hit_cnt, &(ctx->scan_mid), ctx->thread_id);
		if (scan_ret > 0)
		{
			hit_cnt += scan_ret;
		}
		goto decide;
	}

	if ((protocol_field == PXY_CTRL_HTTP_REQ_HDR) || (protocol_field == PXY_CTRL_HTTP_RES_HDR))
	{
		table_id = (protocol_field == PXY_CTRL_HTTP_REQ_HDR) ? g_pangu_rt->scan_table_id[type][PXY_CTRL_HTTP_REQ_HDR] : g_pangu_rt->scan_table_id[type][PXY_CTRL_HTTP_RES_HDR];

		const char * str_field_name = NULL;
		scan_ret = Maat_set_scan_status(g_pangu_rt->maat[type], &(ctx->scan_mid), MAAT_SET_SCAN_DISTRICT,
				   str_field_name, strlen(str_field_name));
		assert(scan_ret == 0);
		scan_ret = Maat_full_scan_string(g_pangu_rt->maat[type], table_id,
			CHARSET_UTF8, value, strlen(value),
			ctx->result + hit_cnt, NULL, MAX_SCAN_RESULT - hit_cnt, &(ctx->scan_mid), ctx->thread_id);
		if (scan_ret > 0)
		{
			hit_cnt += scan_ret;
		}
		goto decide;
	}

	if ((protocol_field == PXY_CTRL_HTTP_REQ_BODY) || protocol_field == PXY_CTRL_HTTP_RES_BODY)
	{
		assert(ctx->sp == NULL);
		table_id = protocol_field == PXY_CTRL_HTTP_REQ_BODY ? g_pangu_rt->scan_table_id[type][PXY_CTRL_HTTP_REQ_BODY] : g_pangu_rt->scan_table_id[type][PXY_CTRL_HTTP_RES_BODY];
		ctx->sp = Maat_stream_scan_string_start(g_pangu_rt->maat[type], table_id, ctx->thread_id);
		scan_ret = Maat_stream_scan_string(&(ctx->sp), CHARSET_UTF8, (const char *) value, (int) strlen(value),
				ctx->result + hit_cnt, NULL, MAX_SCAN_RESULT - hit_cnt, &(ctx->scan_mid));
		if (scan_ret > 0)
		{
			hit_cnt += scan_ret;
		}
		Maat_stream_scan_string_end(&(ctx->sp));
		ctx->sp = NULL;
		goto decide;
	}

	scan_ret = Maat_full_scan_string(g_pangu_rt->maat[type], g_pangu_rt->scan_table_id[type][protocol_field],
									CHARSET_UTF8, value, strlen(value),
									ctx->result+hit_cnt, NULL, MAX_SCAN_RESULT-hit_cnt,
									&(ctx->scan_mid), ctx->thread_id);
	if(scan_ret>0)
	{
		hit_cnt+=scan_ret;
	}
decide:
	if (hit_cnt > 0)
	{
		ctx->action = decide_ctrl_action(ctx->result, hit_cnt, &ctx->enforce_rules, &ctx->n_enforce);
		ctx->hit_cnt = hit_cnt;
		cJSON  *execute_obj=NULL, *hit_obj=NULL;
		hit_obj = cJSON_CreateObject();
		cJSON_AddItemToObject(data_obj, "hitPolicyList", hit_obj);
		if (ctx->hit_cnt >= 1)
		{
			for (i = 0; i < ctx->hit_cnt; i++)
			{
				cJSON_AddNumberToObject(hit_obj, "policyId", ctx->result[i].config_id);
			}
		}
		/*executePolicyList **/
		execute_obj = cJSON_CreateObject();
		cJSON_AddItemToObject(data_obj, "executePolicyList", execute_obj);
		cJSON_AddNumberToObject(execute_obj, "policyId", ctx->enforce_rules[0].config_id);
	}
	return ;
}

char * verify_policy_str_to_addr()
{
	return NULL;
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

int pangu_policy_init(struct verify_proxy * verify, const char* profile_path)
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
	table_name[PXY_CTRL_IP] = "TSG_OBJ_IP_ADDR";
	table_name[PXY_CTRL_HTTP_URL] = "TSG_FIELD_HTTP_URL";
	table_name[PXY_CTRL_HTTP_FQDN] = "TSG_FIELD_HTTP_HOST";
	table_name[PXY_CTRL_HTTP_REQ_HDR] = "TSG_FIELD_HTTP_REQ_HDR";
	table_name[PXY_CTRL_HTTP_REQ_BODY] = "TSG_FIELD_HTTP_REQ_CONTENT";
	table_name[PXY_CTRL_HTTP_RES_HDR] = "TSG_FIELD_HTTP_RES_HDR";
	table_name[PXY_CTRL_HTTP_RES_BODY] = "TSG_FIELD_HTTP_RES_CONTENT";
	table_name[PXY_CTRL_SUBSCRIBE_ID] = "TSG_OBJ_SUBSCRIBER_ID";
	for (int i = 0; i < __SCAN_TABLE_MAX; i++)
	{
		g_pangu_rt->scan_table_id[PXY_TABLE_MANIPULATION][i] = Maat_table_register(g_pangu_rt->maat[PXY_TABLE_MANIPULATION], table_name[i]);

		printf("%p table_name %s, table id %d, i = %d\n", g_pangu_rt->maat[PXY_TABLE_MANIPULATION], table_name[i], g_pangu_rt->scan_table_id[PXY_TABLE_MANIPULATION][i], i);
		if (g_pangu_rt->scan_table_id[PXY_TABLE_MANIPULATION][i] < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Pangu HTTP Maat table %s register failed.", table_name[i]);
			goto error_out;
		}
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

int security_policy_init(struct verify_proxy * verify, const char* profile_path)
{
	int ret = -1;

	g_pangu_rt->maat[PXY_TABLE_SECURITY] = create_maat_feather("static", profile_path, "MAAT", "table_info_tsg", g_pangu_rt->thread_num, g_pangu_rt->local_logger);
	if (!g_pangu_rt->maat[PXY_TABLE_SECURITY])
	{
		goto error_out;
	}
	const char * table_name[__SECURITY_TABLE_MAX];
	table_name[PXY_SECURITY_IP] = "TSG_OBJ_IP_ADDR";
	table_name[PXY_SECURITY_HTTP_URL] = "TSG_FIELD_HTTP_URL";
	table_name[PXY_SECURITY_HTTP_FQDN] = "TSG_FIELD_HTTP_HOST";
	table_name[PXY_SECURITY_HTTP_REQ_HDR] = "TSG_FIELD_HTTP_REQ_HDR";
	table_name[PXY_SECURITY_HTTP_REQ_BODY] = "TSG_FIELD_HTTP_REQ_CONTENT";
	table_name[PXY_SECURITY_HTTP_RES_HDR] = "TSG_FIELD_HTTP_RES_HDR";
	table_name[PXY_SECURITY_HTTP_RES_BODY] = "TSG_FIELD_HTTP_RES_CONTENT";
	table_name[PXY_SECURITY_SUBSCRIBE_ID] = "TSG_OBJ_SUBSCRIBER_ID";
	table_name[PXY_SECURITY_HTTPS_SNI] = "TSG_FIELD_SSL_SNI";
	table_name[PXY_SECURITY_HTTPS_CN] = "TSG_FIELD_SSL_CN";
	table_name[PXY_SECURITY_HTTPS_SAN] = "TSG_FIELD_SSL_SAN";
	table_name[PXY_SECURITY_DNS_QNAME] = "TSG_FIELD_DNS_QNAME";
	table_name[PXY_SECURITY_MAIL_ACCOUNT] = "TSG_FIELD_MAIL_ACCOUNT";
	table_name[PXY_SECURITY_MAIL_FROM] = "TSG_FIELD_MAIL_FROM";
	table_name[PXY_SECURITY_MAIL_TO] = "TSG_FIELD_MAIL_TO";
	table_name[PXY_SECURITY_MAIL_SUBJECT] = "TSG_FIELD_MAIL_SUBJECT";
	table_name[PXY_SECURITY_MAIL_CONTENT] = "TSG_FIELD_MAIL_CONTENT";
	table_name[PXY_SECURITY_MAIL_ATT_NAME] = "TSG_FIELD_MAIL_ATT_NAME";
	table_name[PXY_SECURITY_MAIL_ATT_CONTENT] = "TSG_FIELD_MAIL_ATT_CONTENT";
	table_name[PXY_SECURITY_FTP_URI] = "TSG_FIELD_FTP_URI";
	table_name[PXY_SECURITY_FTP_CONTENT] = "TSG_FIELD_FTP_CONTENT";
	table_name[PXY_SECURITY_FTP_ACCOUNT] = "TSG_FIELD_MAIL_ATT_NAME";

	for (int i = 0; i < __SECURITY_TABLE_MAX; i++)
	{
		g_pangu_rt->scan_table_id[PXY_TABLE_SECURITY][i] = Maat_table_register(g_pangu_rt->maat[PXY_TABLE_SECURITY], table_name[i]);
		printf("SECURITY: %p table_name %s, table id %d, i = %d\n", g_pangu_rt->maat[PXY_TABLE_SECURITY], table_name[i], g_pangu_rt->scan_table_id[PXY_TABLE_SECURITY][i], i);
		if (g_pangu_rt->scan_table_id[PXY_TABLE_SECURITY][i] < 0)
		{
			mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Security policy maat table %s register failed.", table_name[i]);
			goto error_out;
		}
	}
	ret = 0;
error_out:
	return ret;
}

