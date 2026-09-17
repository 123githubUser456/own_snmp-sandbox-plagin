#include <base.h>
#include <base_parse.h>

#include "sandbox.h"

#define SANDBOX_LOG_TAG "sandbox.so >> "

#define SANDBOX_ERROR(_text_, ...) ERROR(SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)
#define SANDBOX_INFO(_text_, ...) INFO(SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)
#define SANDBOX_DEBUG(_condition_, _text_, ...) DEBUG(_condition_, SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)

#define UBUS_FIRST_SUBID_DYN_TABLE 1
#define UBUS_COL_COUNT_DYN_TABLE 3
#define UBUS_DYNTABLE_CREATE_INDEX 1

#define UBUS_CACHE_TTL		1

enum {
	DYNTABLE_INDEX,
    DYNTABLE_NAME,
    DYNTABLE_PATH,
    DYNTABLE_COUNT
};

static const base_entry_parse_policy_t ubus_dyntable_policy[] = {
	{ DYNTABLE_INDEX,	BASE_PARSE_INDEX, base_hook_u16_to_index },
    { DYNTABLE_NAME,		BASE_PARSE_DYNAMIC, base_hook_str_to_octetstr },
    { DYNTABLE_PATH, 	BASE_PARSE_DYNAMIC, base_hook_str_to_octetstr },
    { 0, 0, NULL }
};

typedef struct {
    unsigned char pending;
    unsigned char has_name;
    unsigned char has_value;
    char name[BASE_DATA_STR_LEN + 1];
    char value[BASE_DATA_STR_LEN + 1];
} ubus_dyntable_set_req_t;

struct ubus_context *ctx;
base_cache_t ubus_dyntable_cache;
static ubus_dyntable_set_req_t ubus_dyntable_set_req;

// ====[ubus data - dynamic table]====
/* sandbox: 1.3.6.1.4.1.60641.1.6.1 - start rw dynamic table (A) */

// TABLE (A) - envi (./tubus):
// _______index______NAME_____PATH__
// 0    |_XXXXXX_|_XXXXXXXX_|_XXXXX_| - entry->index
// 1    |_XXXXXX_|_XXXXXXXX_|_XXXXX_|
// 2    |_XXXXXX_|_XXXXXXXX_|_XXXXX_|

static oid ubus_dyntable_branch[] = { 1, 3, 6, 1, 4, 1, 60641, 1, 6};

enum {
    UBUS_ARRAY_ATTR,
    UBUS_ARRAY_ATTR_MAX,
};

static const struct blobmsg_policy ubus_dyntable_msg_policy[] = {
    { .name = "envi", .type = BLOBMSG_TYPE_ARRAY },
};

static void ubus_dyntable_upd_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    base_cache_t *cache = (base_cache_t *) req->priv;
    struct blob_attr *tb[UBUS_ARRAY_ATTR_MAX] = { 0 };
    int res;

    (void) type;

    if (!msg)
        return;

    blobmsg_parse(ubus_dyntable_msg_policy, UBUS_ARRAY_ATTR_MAX, tb,
                  blobmsg_data(msg), blobmsg_len(msg));

    if (!tb[UBUS_ARRAY_ATTR]) {
        SANDBOX_ERROR("ubus_dyntable_upd_cb: no \"envi\" attr\n");
        return;
    }

    res = base_table_parse(cache, tb[UBUS_ARRAY_ATTR], ubus_dyntable_policy, NULL);
    if (res != BASE_OK)
        SANDBOX_ERROR("ubus_dyntable_upd_cb: base_table_parse err\n");
}

static int ubus_dyntable_update(base_cache_t *cache)
{
	uint32_t id;
	int res;

	if (!ctx)
		return BASE_ERR;

	res = ubus_lookup_id(ctx, "/test", &id);

	if (res)
		return BASE_ERR;

	res = ubus_invoke(ctx, id, "get_envi", NULL,
						ubus_dyntable_upd_cb, cache, 500);
		
	if (res)
		return BASE_ERR;

	return BASE_OK;
}

static void ubus_dyntable_set_clear(void)
{
    memset(&ubus_dyntable_set_req, 0, sizeof(ubus_dyntable_set_req));
}

static int ubus_dyntable_set_prepare(unsigned int subid, uint32_t index,
        const base_cell_t *cell)
{
    if (subid == UBUS_FIRST_SUBID_DYN_TABLE + DYNTABLE_INDEX)
        return SNMP_ERR_READONLY;

    if (index != UBUS_DYNTABLE_CREATE_INDEX)
        return SNMP_ERR_NOSUCHNAME;

    if (cell->asn_type != ASN_OCTET_STR)
        return SNMP_ERR_WRONGTYPE;

    ubus_dyntable_set_req.pending = 1;

    if (subid == UBUS_FIRST_SUBID_DYN_TABLE + DYNTABLE_NAME) {
        if (ubus_dyntable_set_req.has_name)
            return SNMP_ERR_INCONSISTENTVALUE;

        memcpy(ubus_dyntable_set_req.name, cell->data_str, (size_t)cell->data64);
        ubus_dyntable_set_req.name[cell->data64] = '\0';
        ubus_dyntable_set_req.has_name = 1;
        return SNMP_ERR_NOERROR;
    }

    if (subid == UBUS_FIRST_SUBID_DYN_TABLE + DYNTABLE_PATH) {
        if (ubus_dyntable_set_req.has_value)
            return SNMP_ERR_INCONSISTENTVALUE;

        memcpy(ubus_dyntable_set_req.value, cell->data_str, (size_t)cell->data64);
        ubus_dyntable_set_req.value[cell->data64] = '\0';
        ubus_dyntable_set_req.has_value = 1;
        return SNMP_ERR_NOERROR;
    }

    return SNMP_ERR_NOSUCHNAME;
}

static int ubus_dyntable_set_commit(base_cache_t *cache)
{
    struct blob_buf b = { 0 };
    uint32_t id;
    int res;

    if (!ubus_dyntable_set_req.pending) {
        ubus_dyntable_set_clear();
        return SNMP_ERR_GENERR;
    }

    if (!ubus_dyntable_set_req.has_name || !ubus_dyntable_set_req.has_value) {
        ubus_dyntable_set_clear();
        return SNMP_ERR_INCONSISTENTVALUE;
    }

    if (!ctx) {
        ubus_dyntable_set_clear();
        return SNMP_ERR_GENERR;
    }

    res = ubus_lookup_id(ctx, "/test", &id);
    if (res) {
        SANDBOX_ERROR("ubus_dyntable_set: lookup failed (%d)\n", res);
        ubus_dyntable_set_clear();
        return base_ubus_status_to_snmp_error(res);
    }

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "name", ubus_dyntable_set_req.name);
    blobmsg_add_string(&b, "value", ubus_dyntable_set_req.value);

    res = ubus_invoke(ctx, id, "set_envi", b.head, NULL, NULL, 500);
    blob_buf_free(&b);

    ubus_dyntable_set_clear();

    if (res) {
        SANDBOX_ERROR("ubus_dyntable_set: invoke set_envi failed (%d)\n", res);
        return base_ubus_status_to_snmp_error(res);
    }

    base_cache_invalidate(cache);
    return SNMP_ERR_NOERROR;
}

static int ubus_dyntable_set(base_cache_t *cache, unsigned int subid, uint32_t index,
        unsigned int phase, const base_cell_t *cell)
{
    switch (phase) {
    case BASE_SET_RESERVE1:
        ubus_dyntable_set_clear();
        return SNMP_ERR_NOERROR;

    case BASE_SET_ACTION:
        return ubus_dyntable_set_prepare(subid, index, cell);

    case BASE_SET_COMMIT:
        return ubus_dyntable_set_commit(cache);

    case BASE_SET_UNDO:
        ubus_dyntable_set_clear();
        return SNMP_ERR_NOERROR;
    }

    return SNMP_ERR_GENERR;
}

void init_sandbox(void)
{
	if (base_ubus_init() != BASE_OK) {
        SANDBOX_ERROR("ubus init failed\n");
        return;
    }
        
    ctx = base_ubus_ctx();
    if (!ctx) {
        SANDBOX_ERROR("ubus ctx is NULL\n");
        base_ubus_deinit();
        return;
    }		

	base_cache_init(&ubus_dyntable_cache, UBUS_COL_COUNT_DYN_TABLE, UBUS_FIRST_SUBID_DYN_TABLE,
		BASE_CACHE_DYNAMIC, UBUS_CACHE_TTL, ubus_dyntable_update, ubus_dyntable_set);

	if (base_register_table("sandbox_ubus_dyntable", &ubus_dyntable_cache,
			ubus_dyntable_branch, OID_LENGTH(ubus_dyntable_branch)) != BASE_OK) {
		SANDBOX_ERROR("register sandbox_ubus_dyntable err\n");
		goto clean;
	}

	SANDBOX_INFO("init done\n");
	return;

clean:
	base_unregister_table(&ubus_dyntable_cache);
	base_cache_deinit(&ubus_dyntable_cache);
	ctx = NULL;
	base_ubus_deinit();
	SANDBOX_INFO("clean done\n");
}

void deinit_sandbox(void)
{
	base_unregister_table(&ubus_dyntable_cache);
	base_cache_deinit(&ubus_dyntable_cache);
	ctx = NULL;
	base_ubus_deinit();
	SANDBOX_INFO("deinit\n");
}