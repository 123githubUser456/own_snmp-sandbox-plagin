#define _GNU_SOURCE 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "libubox/blob.h" 
#include "libubox/blobmsg.h"
#include "libubus.h"

static struct ubus_context *ctx;
static struct blob_buf b;
extern char **environ;

enum {
    SET_NAME,
    SET_VALUE,
    SET_N_ARGS
};

static int get_envi(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg);
static int print_uptime(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg);
static int set_envi(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg);

static const struct blobmsg_policy set_policy[] = {
    [SET_NAME] = {
        .name = "name",
        .type = BLOBMSG_TYPE_STRING
    },
    [SET_VALUE] = {
        .name = "value",
        .type = BLOBMSG_TYPE_STRING
    }
};

static const struct ubus_method test_object_methods[] = {
	UBUS_METHOD_NOARG("get_envi", get_envi),
	UBUS_METHOD_NOARG("print_uptime", print_uptime),
	UBUS_METHOD("set_envi", set_envi, set_policy),
};

static struct ubus_object_type test_object_type =
	UBUS_OBJECT_TYPE("test", test_object_methods);

static struct ubus_object test_object = {
	.name = "/test",
	.type = &test_object_type,
	.methods = test_object_methods,
	.n_methods = ARRAY_SIZE(test_object_methods),
};

static int set_envi(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg)
{
	const char *name;
	const char *value;
	struct blob_attr *tb[SET_N_ARGS] = { 0 };

	blobmsg_parse(set_policy, SET_N_ARGS, tb,
				blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[SET_NAME] || !tb[SET_VALUE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_get_string(tb[SET_NAME]);
	value =  blobmsg_get_string(tb[SET_VALUE]);

	if (*name == '\0' || *value == '\0') 
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (setenv(name, value, 1) != 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	return UBUS_STATUS_OK;
}

static int get_envi(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg)
{
	char **envi = environ;
	int i = 2;

	blob_buf_init(&b, 0);
	
	void *array = blobmsg_open_array(&b, "envi");
	while (*envi != NULL) {
		char *p = strchr(*envi, '=');

		if (p == NULL) {
			envi++;
			continue;
		}

		size_t name_len = (size_t) (p - *envi); 
		char name[name_len + 1]; /* '\0' */
		strlcpy(name, *envi, name_len + 1);
		void *arr = blobmsg_open_array(&b, "");
		blobmsg_add_u16(&b, "", i++);
		blobmsg_add_string(&b, "", name);
		blobmsg_add_string(&b, "", p + 1);
		blobmsg_close_array(&b, arr);
		envi++;
	}
	blobmsg_close_array(&b, array);
	return ubus_send_reply(ctx, req, b.head);
}

static int print_uptime(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg)
{
	struct timespec uptime;

	blob_buf_init(&b, 0);

	if (clock_gettime(CLOCK_MONOTONIC, &uptime) != 0)
		uptime.tv_sec = 0;

	blobmsg_add_string(&b, "message", "Hello UBUS!");
	blobmsg_add_u32(&b, "uptime", (uint32_t) uptime.tv_sec);

	return ubus_send_reply(ctx, req, b.head);
}

int main(int argc, char *argv[])
{
	ctx = ubus_connect(NULL);
	if(ctx == NULL) {
		printf("ubus_connect() err\n");
		return 1;
	}

	if (ubus_add_object(ctx, &test_object) != 0) {
		printf("ubus_add_object() error\n");
		ubus_free(ctx);
		return 1;
	}

	uloop_init();
	ubus_add_uloop(ctx);
	uloop_run();

	uloop_done();

	blob_buf_free(&b);
	ubus_free(ctx);

	return 0;
}