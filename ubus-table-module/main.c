#define _GNU_SOURCE 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "libubox/blob.h" 
#include "libubox/blobmsg.h"
#include "libubus.h"

#define LEN_IP 16
#define LEN_MAC 18

enum {
	TABLE_INDEX = 5,
    TABLE_IP,
    TABLE_MASK,
    TABLE_MAC
};

static struct ubus_context *ctx;
static struct blob_buf b;

typedef struct eth_if {
	char ip[LEN_IP];
	char mask[LEN_IP];
	char mac[LEN_MAC];
} eth_if_t;

eth_if_t eth[3] = {	
					{.ip = "192.168.1.1", .mask = "255.255.255.0", .mac = "AA:BB:CC:DD:EE:FF"},
					{.ip = "192.168.1.2", .mask = "255.255.255.0", .mac = "A1:B2:C3:D4:E5:F6"},
					{.ip = "192.168.1.3", .mask = "255.255.255.0", .mac = "11:22:33:44:55:66"} 
				};

enum {
    SET_LINE,
	SET_COLUMN,
	SET_VALUE,
    SET_N_ARGS
};

static int get(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg);
static int set(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg);

static const struct blobmsg_policy set_policy[] = {
    [SET_LINE] = {
        .name = "line",
        .type = BLOBMSG_TYPE_INT32
    },
	[SET_COLUMN] = {
        .name = "column",
        .type = BLOBMSG_TYPE_INT32
    },
	[SET_VALUE] = {
		.name = "value",
		.type = BLOBMSG_TYPE_STRING
	}
};

static const struct ubus_method module_object_methods[] = {
	UBUS_METHOD_NOARG("get", get),
	UBUS_METHOD("set", set, set_policy),
};

static struct ubus_object_type module_object_type =
	UBUS_OBJECT_TYPE("obj", module_object_methods);

static struct ubus_object test_object = {
	.name = "/ubus-table-module",
	.type = &module_object_type,
	.methods = module_object_methods,
	.n_methods = ARRAY_SIZE(module_object_methods),
};

static int set(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg)
{
	int line, column;
	const char *value;
	struct blob_attr *tb[SET_N_ARGS] = { 0 };

	blobmsg_parse(set_policy, SET_N_ARGS, tb,
				blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[SET_LINE] || !tb[SET_COLUMN] || !tb[SET_VALUE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	line = blobmsg_get_u32(tb[SET_LINE]) - 1;
	column = blobmsg_get_u32(tb[SET_COLUMN]);
	value =  blobmsg_get_string(tb[SET_VALUE]);

	if (line > 3 || *value == '\0') 
		return UBUS_STATUS_INVALID_ARGUMENT;

	// validate.. done))
	switch (column) {
		case TABLE_IP: strlcpy(eth[line].ip, value, LEN_IP); break;
		case TABLE_MASK: strlcpy(eth[line].mask, value, LEN_IP); break;
		case TABLE_MAC: strlcpy(eth[line].mac, value, LEN_MAC); break;
		default: return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return UBUS_STATUS_OK;
}

static int get(struct ubus_context *ctx, 
			struct ubus_object *obj, struct ubus_request_data *req, 
			const char *method, struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	void *array = blobmsg_open_array(&b, "array");
	for (int i = 0; i < 3; i++) {
		void *arr = blobmsg_open_array(&b, "");
		blobmsg_add_u16(&b, "index", i + 1);
		blobmsg_add_string(&b, "ip", eth[i].ip);
		blobmsg_add_string(&b, "mask", eth[i].mask);
		blobmsg_add_string(&b, "mac", eth[i].mac);
		blobmsg_close_array(&b, arr);
	}
	blobmsg_close_array(&b, array);

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