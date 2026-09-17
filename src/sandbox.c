#include <base.h>
#include <base_parse.h>

#include "sandbox.h"

#define SANDBOX_LOG_TAG "sandbox.so >> "

#define SANDBOX_ERROR(_text_, ...) ERROR(SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)
#define SANDBOX_INFO(_text_, ...) INFO(SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)
#define SANDBOX_DEBUG(_condition_, _text_, ...) DEBUG(_condition_, SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)

#define SANDBOX_FIRST_SUBID_SCAL 1
#define SANDBOX_COL_COUNT_SCAL 2

#define UBUS_FIRST_SUBID_DYN_TABLE 1
#define UBUS_COL_COUNT_DYN_TABLE 3
#define UBUS_DYNTABLE_CREATE_INDEX 1

#define UBUS_FIRST_SUBID_TABLE 1
#define UBUS_COL_COUNT_TABLE 4

#define SANDBOX_CACHE_TTL 	5
#define UBUS_CACHE_TTL		1

enum {
    COL_REQ_CNT,
    COL_SANDBOX_STR,
    COL_NUM
};

enum {
	COL_INDEX,
    COL_NAME,
    COL_PATH,
    COL_COUNT
};

enum {
	TABLE_INDEX,
    TABLE_IP,
    TABLE_MASK,
    TABLE_MAC,
    TABLE_NUM
};

static const base_entry_parse_policy_t ubus_table_policy[] = {
	{TABLE_INDEX, 	BASE_PARSE_INDEX,   base_hook_u16_to_index    },
    {TABLE_IP, 		BASE_PARSE_DYNAMIC,	base_hook_str_to_octetstr},
	{TABLE_MASK,	BASE_PARSE_DYNAMIC,	base_hook_str_to_octetstr},
    {TABLE_MAC,		BASE_PARSE_DYNAMIC, base_hook_str_to_octetstr},
    {0, 0, NULL }
};

static const base_entry_parse_policy_t ubus_dyntable_policy[] = {
	{ COL_INDEX,	BASE_PARSE_INDEX, base_hook_u16_to_index },
    { COL_NAME,		BASE_PARSE_DYNAMIC, base_hook_str_to_octetstr },
    { COL_PATH, 	BASE_PARSE_DYNAMIC, base_hook_str_to_octetstr },
    { 0, 0, NULL }
};

typedef struct {
    unsigned char pending;
    unsigned char has_name;
    unsigned char has_value;
    char name[BASE_DATA_STR_LEN + 1];
    char value[BASE_DATA_STR_LEN + 1];
} ubus_dyntable_set_req_t;

typedef struct {
    unsigned char pending;
    unsigned int column;
    uint32_t line;
    char value[BASE_DATA_STR_LEN + 1];
} ubus_table_set_req_t;

struct ubus_context *ctx;

base_cache_t sandbox_cache;
base_cache_t ubus_dyntable_cache;
base_cache_t ubus_table_cache;

static ubus_dyntable_set_req_t ubus_dyntable_set_req;
static ubus_table_set_req_t ubus_table_set_req;


int32_t req_cnt = 0;
char sandbox_str[64] = { 0 };

// ====[local data - scalars]====
/* sandbox: 1.3.6.1.4.1.60641.1.5.1 - ro request_counter integer32, [src - sandbox.so]*/
/* sandbox: 1.3.6.1.4.1.60641.1.5.2 - rw sandbox_string octet str [64], [src - sandbox.so]*/

// ====[ubus data - dynamic table]====
/* sandbox: 1.3.6.1.4.1.60641.1.6.1 - start rw dynamic table (A) */

// ====[ubus data - static table]====
/* sandbox: 1.3.6.1.4.1.60641.1.7.1 - start rw table (B)*/

// TABLE (A) - envi (./tubus):
// _______index______NAME_____PATH__
// 0    |_XXXXXX_|_XXXXXXXX_|_XXXXX_| - entry->index
// 1    |_XXXXXX_|_XXXXXXXX_|_XXXXX_|
// 2    |_XXXXXX_|_XXXXXXXX_|_XXXXX_|

// TABLE (B) - custom table (./ubus-table-module):
// _______index__IP ADDR___MAC_ADRR____MASK__
// ETH0_|__XXXX_|_XXXXXX_|_XXXXXXXX_|_XXXXX_| - entry->index
// ETH1_|__XXXX_|_XXXXXX_|_XXXXXXXX_|_XXXXX_|
// ETH2_|__XXXX_|_XXXXXX_|_XXXXXXXX_|_XXXXX_|
static oid sandbox_branch[] = { 1, 3, 6, 1, 4, 1, 60641, 1, 5};
static oid ubus_dyntable_branch[] = { 1, 3, 6, 1, 4, 1, 60641, 1, 6};
static oid ubus_table_branch[] = { 1, 3, 6, 1, 4, 1, 60641, 1, 7};

static int sandbox_update(base_cache_t *cache)
{
	/* Для скаляров используется первая и единственная строка кэша. */
    base_entry_t *entry = base_cache_entry_first(cache);

    if (!entry) {
        entry = base_cache_entry_alloc(cache);
        if (!entry)
            return BASE_ERR;
    } else {
        /* Перед новым заполнением старые значения надо сбросить. */
        base_cache_entry_unset(entry, cache->column_count);
    }

    entry->cells[COL_REQ_CNT].set = BASE_CELL_SET;
    entry->cells[COL_REQ_CNT].asn_type = ASN_INTEGER;
    entry->cells[COL_REQ_CNT].data64 = ++req_cnt;

	 /* OCTET STRING хранится как байты + длина, не как C-строка. */
    entry->cells[COL_SANDBOX_STR].set = BASE_CELL_SET;
    entry->cells[COL_SANDBOX_STR].asn_type = ASN_OCTET_STR;
    memcpy(entry->cells[COL_SANDBOX_STR].data_str, sandbox_str, BASE_STRLEN(sandbox_str));
    entry->cells[COL_SANDBOX_STR].data64 = BASE_STRLEN(sandbox_str);

    return BASE_OK;
}

static int sandbox_set(base_cache_t *cache, unsigned int subid, uint32_t index,
        unsigned int phase, const base_cell_t *cell)
{
    (void)index;

    switch (phase) {
    case BASE_SET_RESERVE1:
		return SNMP_ERR_NOERROR;

    case BASE_SET_ACTION:
		++req_cnt;
        if ((subid == SANDBOX_FIRST_SUBID_SCAL + COL_SANDBOX_STR) && (cell->asn_type == ASN_OCTET_STR)) {
            memcpy(sandbox_str, cell->data_str, BASE_STRLEN(cell->data_str));
            return SNMP_ERR_NOERROR;
        }
        return SNMP_ERR_WRONGTYPE;

    case BASE_SET_COMMIT:
        base_cache_invalidate(cache);
        return SNMP_ERR_NOERROR;

    case BASE_SET_UNDO:
        return SNMP_ERR_NOERROR;
    }

    return SNMP_ERR_GENERR;
}

enum {
    UBUS_ARRAY_ATTR,
    UBUS_ARRAY_ATTR_MAX,
};

static const struct blobmsg_policy ubus_dyntable_msg_policy[] = {
    { .name = "envi", .type = BLOBMSG_TYPE_ARRAY },
};

static const struct blobmsg_policy ubus_table_msg_policy[] = {
    { .name = "array", .type = BLOBMSG_TYPE_ARRAY },
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

	++req_cnt;
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
    if (subid == UBUS_FIRST_SUBID_DYN_TABLE + COL_INDEX)
        return SNMP_ERR_READONLY;

    if (index != UBUS_DYNTABLE_CREATE_INDEX)
        return SNMP_ERR_NOSUCHNAME;

    if (cell->asn_type != ASN_OCTET_STR)
        return SNMP_ERR_WRONGTYPE;

    ubus_dyntable_set_req.pending = 1;

    if (subid == UBUS_FIRST_SUBID_DYN_TABLE + COL_NAME) {
        if (ubus_dyntable_set_req.has_name)
            return SNMP_ERR_INCONSISTENTVALUE;

		if (ubus_dyntable_set_req.has_value)
			++req_cnt;

        memcpy(ubus_dyntable_set_req.name, cell->data_str, (size_t)cell->data64);
        ubus_dyntable_set_req.name[cell->data64] = '\0';
        ubus_dyntable_set_req.has_name = 1;
        return SNMP_ERR_NOERROR;
    }

    if (subid == UBUS_FIRST_SUBID_DYN_TABLE + COL_PATH) {
        if (ubus_dyntable_set_req.has_value)
            return SNMP_ERR_INCONSISTENTVALUE;

		if (ubus_dyntable_set_req.has_name)
			++req_cnt;

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

static void ubus_table_upd_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    base_cache_t *cache = (base_cache_t *) req->priv;
    struct blob_attr *tb[UBUS_ARRAY_ATTR_MAX] = { 0 };
    int res;

    (void) type;

    if (!msg)
        return;

    blobmsg_parse(ubus_table_msg_policy, UBUS_ARRAY_ATTR_MAX, tb,
                  blobmsg_data(msg), blobmsg_len(msg));

    if (!tb[UBUS_ARRAY_ATTR]) {
        SANDBOX_ERROR("ubus_table_upd_cb: no \"array\" attr\n");
        return;
    }

    res = base_table_parse(cache, tb[UBUS_ARRAY_ATTR], ubus_table_policy, NULL);
    if (res != BASE_OK)
        SANDBOX_ERROR("ubus_table_upd_cb: base_table_parse err\n");
}

static int ubus_table_update(base_cache_t *cache)
{
	uint32_t id;
	int res;

	if (!ctx)
		return BASE_ERR;

	++req_cnt;
	res = ubus_lookup_id(ctx, "/ubus-table-module", &id);

	if (res)
		return BASE_ERR;

	res = ubus_invoke(ctx, id, "get", NULL,
						ubus_table_upd_cb, cache, 500);
		
	if (res)
		return BASE_ERR;

	return BASE_OK;
}

static void ubus_table_set_clear(void)
{
    memset(&ubus_table_set_req, 0, sizeof(ubus_table_set_req));
}

static int ubus_table_set_prepare(unsigned int subid, uint32_t index,
        const base_cell_t *cell)
{
    if (subid == UBUS_FIRST_SUBID_DYN_TABLE + TABLE_INDEX)
        return SNMP_ERR_READONLY;

    if (!index)
        return SNMP_ERR_NOSUCHNAME;

    if (cell->asn_type != ASN_OCTET_STR)
        return SNMP_ERR_WRONGTYPE;

    if (ubus_table_set_req.pending)
        return SNMP_ERR_INCONSISTENTVALUE;

    ubus_table_set_req.line = index;
    ubus_table_set_req.column = subid;
    memcpy(ubus_table_set_req.value, cell->data_str, (size_t)cell->data64);
    ubus_table_set_req.value[cell->data64] = '\0';
    ubus_table_set_req.pending = 1;

    return SNMP_ERR_NOERROR;
}

static int ubus_table_set_commit(base_cache_t *cache)
{
    struct blob_buf b = { 0 };
    uint32_t id;
    int res;

    if (!ubus_table_set_req.pending)
        return SNMP_ERR_GENERR;

    if (!ctx)
        return SNMP_ERR_GENERR;

    res = ubus_lookup_id(ctx, "/ubus-table-module", &id);
    if (res) {
        SANDBOX_ERROR("ubus_table_set: lookup failed (%d)\n", res);
        ubus_table_set_clear();
        return base_ubus_status_to_snmp_error(res);
    }

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "line", ubus_table_set_req.line);
    blobmsg_add_u32(&b, "column", ubus_table_set_req.column);
    blobmsg_add_string(&b, "value", ubus_table_set_req.value);

    res = ubus_invoke(ctx, id, "set", b.head, NULL, NULL, 500);
    blob_buf_free(&b);

    ubus_table_set_clear();

    if (res) {
        SANDBOX_ERROR("ubus_table_set: invoke set failed (%d)\n", res);
        return base_ubus_status_to_snmp_error(res);
    }

    base_cache_invalidate(cache);
    return SNMP_ERR_NOERROR;
}

static int ubus_table_set(base_cache_t *cache, unsigned int subid, uint32_t index,
        unsigned int phase, const base_cell_t *cell)
{
    switch (phase) {
    case BASE_SET_RESERVE1:
        ubus_table_set_clear();
        return SNMP_ERR_NOERROR;

    case BASE_SET_ACTION:
        return ubus_table_set_prepare(subid, index, cell);

    case BASE_SET_COMMIT:
        return ubus_table_set_commit(cache);

    case BASE_SET_UNDO:
        ubus_table_set_clear();
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

	base_cache_init(&sandbox_cache, SANDBOX_COL_COUNT_SCAL, SANDBOX_FIRST_SUBID_SCAL,
            BASE_CACHE_DYNAMIC, SANDBOX_CACHE_TTL, sandbox_update, sandbox_set);
	base_cache_init(&ubus_dyntable_cache, UBUS_COL_COUNT_DYN_TABLE, UBUS_FIRST_SUBID_DYN_TABLE,
		BASE_CACHE_DYNAMIC, UBUS_CACHE_TTL, ubus_dyntable_update, ubus_dyntable_set);
	base_cache_init(&ubus_table_cache, UBUS_COL_COUNT_TABLE, UBUS_FIRST_SUBID_TABLE,
		BASE_CACHE_DYNAMIC, UBUS_CACHE_TTL, ubus_table_update, ubus_table_set);

	if (base_register_scalars("sandbox_scal", &sandbox_cache, 
			sandbox_branch, OID_LENGTH(sandbox_branch)) != BASE_OK) {
		SANDBOX_ERROR("register sandbox_scal err\n");
		goto clean;
	}

	if (base_register_table("sandbox_ubus_dyntable", &ubus_dyntable_cache,
			ubus_dyntable_branch, OID_LENGTH(ubus_dyntable_branch)) != BASE_OK) {
		SANDBOX_ERROR("register sandbox_ubus_dyntable err\n");
		goto clean;
	}

	if (base_register_table("sandbox_ubus_table", &ubus_table_cache,
			ubus_table_branch, OID_LENGTH(ubus_table_branch)) != BASE_OK) {
		SANDBOX_ERROR("register sandbox_ubus_table err\n");
		goto clean;
	}

	SANDBOX_INFO("init done\n");
	return;

clean:
	base_unregister_scalars(&sandbox_cache);
	base_unregister_table(&ubus_dyntable_cache);
	base_unregister_table(&ubus_table_cache);
	base_cache_deinit(&sandbox_cache);
	base_cache_deinit(&ubus_dyntable_cache);
	base_cache_deinit(&ubus_table_cache);
	ctx = NULL;
	base_ubus_deinit();
	SANDBOX_INFO("clean done\n");
}

void deinit_sandbox(void)
{
	base_unregister_scalars(&sandbox_cache);
	base_unregister_table(&ubus_dyntable_cache);
	base_unregister_table(&ubus_table_cache);
	base_cache_deinit(&sandbox_cache);
	base_cache_deinit(&ubus_dyntable_cache);
	base_cache_deinit(&ubus_table_cache);
	ctx = NULL;
	base_ubus_deinit();
	SANDBOX_INFO("deinit\n");
}