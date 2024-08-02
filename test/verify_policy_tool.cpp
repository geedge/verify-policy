/*************************************************************************
	> File Name:
	> Author:
	> Mail:
	> Created Time: 2020��05��28�� ������ 19ʱ21��37��
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <cjson/cJSON.h>
#include <sys/stat.h>
#include "utils.h"

enum curl_post_type
{
    CURL_POST_HTTP,
    CURL_POST_SSL,
    __CURL_POST_MAX
};

struct curl_post_data
{
	char *input_result_data;
	char *curl_post_file;
	enum curl_post_type protocol_type;
};

char *curl_read_file(char *result_json_file)
{
	FILE* fp=NULL;
	struct stat file_info;
	stat(result_json_file, &file_info);
	size_t input_sz=file_info.st_size;

	fp=fopen(result_json_file,"r");
	if(fp==NULL)
	{
		return NULL;
	}
	char* input=(char*)malloc(input_sz);
	fread(input,1,input_sz,fp);
	fclose(fp);

	return input;
}

int curl_post_system_cmd(char *result, size_t result_len, char *curl_post_json)
{
	int line_num=0;
    char command[1024] = {0};
	char *cmd_str=NULL;

	snprintf(command, sizeof(command), "curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9994/v1/policy/verify -d@%s", curl_post_json);

	char *p=result;
	char line[2048] = {0};
    FILE *fp = NULL;

    if((fp = popen(command, "r")) == NULL)
	{
        printf("popen error!\n");
        return 0;
    }
	memset(result, 0, result_len);
    while (fgets(line, sizeof(line), fp))
	{
		if((p - result) < (int)result_len)
		{
			if(line_num)
			{
				p += snprintf(p, result_len - (p - result), ",");
			}

			p += snprintf(p, result_len - (p - result), "%s", line);
		}
		line_num++;
    }
    pclose(fp);

	free(cmd_str);
	return 1;
}

int curl_exec_expect_result(char *result, char *input_json_file)
{
	int ret=-1;
	cJSON *result_json=NULL, *input_json=NULL;
	cJSON_bool successful = false;

	result_json = cJSON_Parse(result);
	if(!result_json)
	{
		goto finish;
	}
	input_json = cJSON_Parse(input_json_file);
	if(!input_json)
	{
		goto finish;
	}
	successful = cJSON_Compare(result_json, result_json, true);
	if(successful)
	{
		ret=0;
	}
finish:
	cJSON_Delete(result_json);
	cJSON_Delete(input_json);
	return ret;
}

int call_curl_post(struct curl_post_data *post_data)
{
	int ret=-1;
	char result[81920]={0};

	curl_post_system_cmd(result, sizeof(result), post_data->curl_post_file);

	switch(post_data->protocol_type)
	{
		case CURL_POST_HTTP:
			ret = curl_exec_expect_result(result, post_data->input_result_data);
			break;
		case CURL_POST_SSL:
			break;
		default:
			break;
	}
	return ret;
}

static void help()
{
	fprintf(stderr,
		"verify_policy_test <-j| -t | -c > arg\n"
		"Usage:\n"
		"  -j <post json data>\n"
		"  -t <protocol type>\n"
		"  -c <input json>\n");
	    exit(1);
}

int main(int argc, char ** argv)
{
	int i=0, ret = 0;
	int curl_post_type=0;
	char result_json_file[256]={0};
	char curl_post_file[256]={0};

	if(argc < 3) {help();}
	for (i = 1; i < argc; i++)
	{
        int lastarg = i==argc-1;
		if (!strcmp(argv[i], "-j") && !lastarg)
		{
			 strncpy(curl_post_file, argv[++i], sizeof(curl_post_file));
		}
		else if (!strcmp(argv[i], "-t") && !lastarg)
		{
			sscanf(argv[++i], "%u", &curl_post_type);
		}
		else if (!strcmp(argv[i], "-c") && !lastarg)
		{
			strncpy(result_json_file, argv[++i], sizeof(result_json_file));
		}
		else
		{
			help();
		}
    }
	struct curl_post_data *post_data=NULL;
	post_data = ALLOC(struct curl_post_data, 1);
	post_data->protocol_type=(enum curl_post_type)curl_post_type;
	post_data->input_result_data=curl_read_file(result_json_file);
	post_data->curl_post_file=curl_post_file;

	ret = call_curl_post(post_data);

	return ret;
}
