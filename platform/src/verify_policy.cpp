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

#include <MESA/MESA_prof_load.h>
#include "verify_policy.h"

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
	struct evbuffer * evbuf_body = NULL;
	char *input = NULL; ssize_t inputlen=0;
	char *http_payload_string= NULL; cJSON  *http_payload=NULL;

	if (evhttp_request_get_command(evh_req) != EVHTTP_REQ_POST)
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "FAILED (post type)");
		goto error;
	}

	evbuf_body = evhttp_request_get_input_buffer(evh_req);
	if (!evbuf_body || 0==(inputlen = evbuffer_get_length(evbuf_body)) ||!(input = (char *)evbuffer_pullup(evbuf_body,inputlen)))
	{
		log_fatal(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "Failed to get post data information.");
		goto error;
	}
	log_info(g_verify_proxy->logger, MODULE_VERIFY_POLICY, "[I] Request library search: %s", evhttp_request_get_uri(evh_req));

	http_payload = get_library_search_query(input, inputlen);
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
    int socktype = SOCK_STREAM | SOCK_NONBLOCK;

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

