/*************************************************************************
	> File Name:
	> Author:
	> Mail:
	> Created Time: 2020��05��28�� ������ 19ʱ21��37��
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <cjson/cJSON.h>
#include <sys/stat.h>
#include <gtest/gtest.h>

#include <MESA/MESA_prof_load.h>

#include "verify_policy.h"
#include "utils.h"

cJSON *verify_policy_result;
cJSON *verify_policy_request;

struct verify_policy * g_verify_proxy = NULL;
extern cJSON *get_library_search_query(const char *data, ssize_t data_len);
extern cJSON *get_verify_policy_query(const char *data, ssize_t data_len, int thread_id);

int load_json_file_system_cmd(const char *load_json_file, const char *run_json_file, int backup)
{
    char command[1024] = {0};

	if(backup)
	{
		snprintf(command, sizeof(command), "cp ./resource/%s ./resource/backup.json", run_json_file);
		system(command);
	}

	memset(command, 0, sizeof(command));
	snprintf(command, sizeof(command), "cp ./resource/%s ./resource/%s", load_json_file, run_json_file);
	system(command);
	return 0;
}

static char *select_hit_policy_result_item(int gtest_id)
{
	if(verify_policy_result == NULL || verify_policy_result->type!=cJSON_Array)
	{	
		return NULL;
	}

	int foreach=0;
	char *hit_policy_result = NULL;
	cJSON *subitem = NULL;

	for (subitem = verify_policy_result->child; subitem != NULL; subitem = subitem->next)
	{
		if(foreach == gtest_id)
		{
			hit_policy_result = cJSON_PrintUnformatted(subitem);
			break;
		}
		foreach++;
	}
	return hit_policy_result;
}

static char *select_hit_policy_request_item(int gtest_id)
{
	if(verify_policy_request == NULL || verify_policy_request->type!=cJSON_Array)
	{	
		return NULL;
	}

	int foreach=0;
	char *hit_policy_request = NULL;
	cJSON *subitem = NULL;

	for (subitem = verify_policy_request->child; subitem != NULL; subitem = subitem->next)
	{
		if(foreach == gtest_id)
		{
			hit_policy_request = cJSON_PrintUnformatted(subitem);
			break;
		}
		foreach++;
	}
	return hit_policy_request;
}

TEST(LibrarySearch, HitFqdnEntry)
{
	const char *hit_policy_request = "{\"ip\":null,\"fqdn\":\"www.126.com\",\"vsys_id\":1}";
	const char *hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"hit_library\":[{\"tag_ids\":\"1\"}]},\"success\":true}";

	cJSON *result_json = get_library_search_query(hit_policy_request, strlen(hit_policy_request));
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_list = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_list != NULL);

	int equal = strncasecmp(hit_policy_list, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_list);

	hit_policy_request = "{\"ip\":null,\"fqdn\":\"www.baidu.com\",\"vsys_id\":1}";
	hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"hit_library\":[{\"tag_ids\":\"2,3\"}]},\"success\":true}";

	result_json = get_library_search_query(hit_policy_request, strlen(hit_policy_request));
	ASSERT_TRUE(result_json != NULL);

	hit_policy_list = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_list != NULL);

	equal = strncasecmp(hit_policy_list, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_list);

	hit_policy_request = "{\"ip\":null,\"fqdn\":\"www.qq.com\",\"vsys_id\":1}";
	hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"hit_library\":[{\"tag_ids\":\"4,5,6\"}]},\"success\":true}";

	result_json = get_library_search_query(hit_policy_request, strlen(hit_policy_request));
	ASSERT_TRUE(result_json != NULL);

	hit_policy_list = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_list != NULL);

	equal = strncasecmp(hit_policy_list, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_list);
}

TEST(LibrarySearch, HitIpEntry)
{
	const char *hit_policy_request = "{\"ip\":\"192.168.1.1\",\"fqdn\":null,\"vsys_id\":1}";
	const char *hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"hit_library\":[{\"tag_ids\":\"11\"}]},\"success\":true}";
	
	cJSON *result_json = get_library_search_query(hit_policy_request, strlen(hit_policy_request));
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_list = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_list != NULL);

	int equal = strncasecmp(hit_policy_list, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_list);

	hit_policy_request ="{\"ip\":\"192.168.1.2\",\"fqdn\":null,\"vsys_id\":1}";
	hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"hit_library\":[{\"tag_ids\":\"12,13\"}]},\"success\":true}";

	result_json = get_library_search_query(hit_policy_request, strlen(hit_policy_request));
	ASSERT_TRUE(result_json != NULL);

	hit_policy_list = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_list != NULL);

	equal = strncasecmp(hit_policy_list, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_list);

	hit_policy_request = "{\"ip\":\"192.168.1.3\",\"fqdn\":null,\"vsys_id\":1}";
	hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"hit_library\":[{\"tag_ids\":\"14,15,16\"}]},\"success\":true}";

	result_json = get_library_search_query(hit_policy_request, strlen(hit_policy_request));
	ASSERT_TRUE(result_json != NULL);

	hit_policy_list = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_list != NULL);

	equal = strncasecmp(hit_policy_list, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_list);
}

TEST(VerifyPolicy, CheckRegexExpression)
{
	const char *hit_policy_request = "{\"verify_list\":[{\"vsys_id\":null,\"verify_regex\":[]}],\"verify_type\":\"regex\"}";
	const char *hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"verify_regex\":[]},\"success\":true}";

	cJSON *result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);

	int equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);

	hit_policy_request = "{\"verify_list\":[{\"vsys_id\":null,\"verify_regex\":[{\"regex_str\":\"asdfasf\",\"is_valid\":null}]}],\"verify_type\":\"regex\"}";
	hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"verify_regex\":[{\"regex_str\":\"asdfasf\",\"is_valid\":1}]},\"success\":true}";

	result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);

	equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);

	hit_policy_request = "{\"verify_list\":[{\"vsys_id\":null,\"verify_regex\":[{\"regex_str\":\"RegexExpress\",\"is_valid\":null},\
{\"regex_str\":\"*RegexExpress\",\"is_valid\":null},{\"regex_str\":\"^\\\\w+([-+.]\\\\w+)*@\\\\w+([-.]\\\\w+)*\\\\.\\\\w+([-.]\\\\w+)*$\",\"is_valid\":null}]}],\"verify_type\":\"regex\"}";
	hit_policy_result="{\"code\":200,\"msg\":\"Success\",\"data\":{\"verify_regex\":[{\"regex_str\":\"RegexExpress\",\"is_valid\":1},{\"regex_str\":\"*RegexExpress\",\"is_valid\":0},\
{\"regex_str\":\"^\\\\w+([-+.]\\\\w+)*@\\\\w+([-.]\\\\w+)*\\\\.\\\\w+([-.]\\\\w+)*$\",\"is_valid\":1}]},\"success\":true}";

	result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);

	equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);

}

TEST(VerifyPolicy, HitIpPolicy)
{
	char *hit_policy_request = select_hit_policy_request_item(0);
	ASSERT_TRUE(hit_policy_request != NULL);
	char *hit_policy_result = select_hit_policy_result_item(0);
	ASSERT_TRUE(hit_policy_result != NULL);

	cJSON *result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);

	int equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);
	FREE(&hit_policy_request);
	FREE(&hit_policy_result);
}

TEST(VerifyPolicy, HitLibraryPolicy)
{
	char *hit_policy_request = select_hit_policy_request_item(1);
	ASSERT_TRUE(hit_policy_request != NULL);
	char *hit_policy_result = select_hit_policy_result_item(1);
	ASSERT_TRUE(hit_policy_result != NULL);

	cJSON *result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);

	int equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);
	FREE(&hit_policy_request);
	FREE(&hit_policy_result);
}

static void reload_maat_config(const char * main_profile)
{
	verify_policy_table_free(main_profile);
	int ret = verify_policy_table_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at init maat module, Exit.");
}

/*Tunnel Endpoint Policy Test**/
TEST(VerifyPolicy, HitTunnelEndpointaPolicy)
{
	reload_maat_config("./conf/verify_policy2.conf");
	char *hit_policy_request = select_hit_policy_request_item(2);
	ASSERT_TRUE(hit_policy_request != NULL);
	char *hit_policy_result = select_hit_policy_result_item(2);
	ASSERT_TRUE(hit_policy_result != NULL);

	cJSON *result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);

	int equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);
	FREE(&hit_policy_request);
	FREE(&hit_policy_result);
}

TEST(VerifyPolicy, HitTunnelEndpointbPolicy)
{
	char *hit_policy_request = select_hit_policy_request_item(3);
	ASSERT_TRUE(hit_policy_request != NULL);
	char *hit_policy_result = select_hit_policy_result_item(3);
	ASSERT_TRUE(hit_policy_result != NULL);

	cJSON *result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);

	int equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);
	FREE(&hit_policy_request);
	FREE(&hit_policy_result);
}

TEST(VerifyPolicy, HitTunnelEndpointPolicy)
{
	char *hit_policy_request = select_hit_policy_request_item(4);
	ASSERT_TRUE(hit_policy_request != NULL);
	char *hit_policy_result = select_hit_policy_result_item(4);
	ASSERT_TRUE(hit_policy_result != NULL);

	cJSON *result_json = get_verify_policy_query(hit_policy_request, strlen(hit_policy_request), 1);
	ASSERT_TRUE(result_json != NULL);

	char *hit_policy_query = cJSON_PrintUnformatted(result_json);
	ASSERT_TRUE(hit_policy_query != NULL);
	printf("hit_policy_query =%s\n", hit_policy_query);

	int equal = strncasecmp(hit_policy_query, hit_policy_result, strlen(hit_policy_result));
	EXPECT_EQ(equal, 0);

	cJSON_Delete(result_json);
	FREE(&hit_policy_query);
	FREE(&hit_policy_request);
	FREE(&hit_policy_result);
}

static char *read_json_file(const char *filename, size_t *input_sz)
{
	FILE* fp=NULL;
	struct stat file_info;
	stat(filename, &file_info);
	*input_sz=file_info.st_size;

	fp=fopen(filename,"r");
	if(fp==NULL)
	{
		return NULL;
	}
	char* input=(char*)malloc(*input_sz);
	fread(input,1,*input_sz,fp);
	fclose(fp);
	return input;
}

cJSON *load_verify_policy_result_by_file(const char *filename, int hit_policy_result)
{
	size_t input_sz = 0;
	char *input = read_json_file(filename, &input_sz);
	if(input == NULL)
	{
		return NULL;
	}

	cJSON* data = cJSON_Parse(input);
	if(data == NULL)
	{
		FREE(&input);
		return NULL;
	}

	if(hit_policy_result)
	{
		verify_policy_result = cJSON_GetObjectItem(data,"Verify_Policy_Result");
	}
	else
	{
		verify_policy_request = cJSON_GetObjectItem(data,"Verify_Policy_Request");
	}

	FREE(&input);
	return data;
}

int main(int argc, char ** argv)
{
	int ret = 0;
	int log_level=0;
	const char * main_profile = "./conf/verify_policy.conf";

	g_verify_proxy = ALLOC(struct verify_policy, 1);
	assert(g_verify_proxy);
	strcpy(g_verify_proxy->name, "verify_policy");

	const char *log_path="./logs/verify_policy.log";
	MESA_load_profile_int_def(main_profile, "SYSTEM", "log_level", &log_level, LOG_FATAL);
	g_verify_proxy->logger = log_handle_create(log_path, log_level);
	CHECK_OR_EXIT(g_verify_proxy->logger != NULL, "Failed at init log module. Exit.");

	g_verify_proxy->nr_work_threads=4;
	ret = verify_policy_table_init(g_verify_proxy, main_profile);
	CHECK_OR_EXIT(ret == 0, "Failed at init maat module, Exit.");

	const char *filename1 = "./resource/HitPolicyResult.json";
	cJSON *data1=load_verify_policy_result_by_file(filename1, 1);
	const char *filename2 = "./resource/HitPolicyRequest.json";
	cJSON *data2=load_verify_policy_result_by_file(filename2, 0);

	testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	if(data1 != NULL)
	{
		cJSON_Delete(data1);
	}
	if(data2 != NULL)
	{
		cJSON_Delete(data2);
	}
	return ret;
}

