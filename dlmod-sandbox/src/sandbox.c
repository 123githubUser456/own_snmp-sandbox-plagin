#include <base.h>
#include <base_parse.h>

#include "sandbox.h"

#define SANDBOX_FIRST_SUBID_SCAL 1
#define SANDBOX_COL_COUNT_SCAL 2

#define UBUS_FIRST_SUBID_SCAL 1
#define UBUS_COL_COUNT_SCAL 2

#define SANDBOX_CACHE_TTL 	5
#define UBUS_CACHE_TTL		1

enum {
    COL_REQ_CNT,
    COL_SANDBOX_STR,
    COL_NUM
};

enum {
    COL_MESSAGE,
    COL_UPTIME,
    COL_COUNT
};

static const base_entry_parse_policy_t ubus_scal_policy[] = {
    { COL_MESSAGE,	BASE_PARSE_DYNAMIC, base_hook_str_to_octetstr },
    { COL_UPTIME, 	BASE_PARSE_DYNAMIC, base_hook_u32_to_timeticks },
    { 0, 0, NULL }
};


struct ubus_context *ctx;
base_cache_t sandbox_cache;
base_cache_t ubus_scal_cache;

int32_t req_cnt = 0;
char sandbox_str[64] = { 0 };
/* sandbox: 1.3.6.1.4.1.60641.1.5 */
// ====[local data - scalars]====
/* sandbox: 1.3.6.1.4.1.60641.1.5.1 - ro request_counter integer32, [src - sandbox.so]*/
/* sandbox: 1.3.6.1.4.1.60641.1.5.2 - rw sandbox_string octet str [64], [src - sandbox.so]*/
// ====[ubus data - scalars]====
/* sandbox: 1.3.6.1.4.1.60641.1.6.1 - ro ubus uptime integer32 */
/* sandbox: 1.3.6.1.4.1.60641.1.6.2 - ro <ubus string> octet str */


/* sandbox: 1.3.6.1.4.1.60641.1.5.5 - rw table (A)*/
// TABLE (A):
// ______IP ADDR___MAC_ADRR____MASK
// ETH0_|_XXXXXX_|_XXXXXXXX_|_XXXXX_| - entry->index
// ETH1_|_XXXXXX_|_XXXXXXXX_|_XXXXX_|
// ETH2_|_XXXXXX_|_XXXXXXXX_|_XXXXX_|
static oid sandbox_branch[] = { 1, 3, 6, 1, 4, 1, 60641, 1, 5};
static oid sandbox_ubus_branch[] = { 1, 3, 6, 1, 4, 1, 60641, 1, 6};

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

static void ubus_scal_upd_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	base_cache_t *cache = (base_cache_t *) req->priv;
    struct blob_attr *entry_attr = msg;
    base_entry_t *entry = base_cache_entry_first(cache);
	
    if (!entry_attr) {
		ERROR("base_cache_entry_first() err\n");
		return;
	}

    if (!entry) {
        entry = base_cache_entry_alloc(cache);
        if (!entry) {
			ERROR("base_cache_entry_alloc() err\n");
			return;
		}
    } else {
        base_cache_entry_unset(entry, cache->column_count);
    }

    if (base_entry_parse(entry, entry_attr, ubus_scal_policy, cache->column_count) == BASE_ERR)
		ERROR("ubus_scal_upd_cb:   base_entry_parse() err\n");
}

static int ubus_scal_update(base_cache_t *cache)
{
	uint32_t id;
	int res;

	if (!ctx)
		return BASE_ERR;

	++req_cnt;
	res = ubus_lookup_id(ctx, "/test", &id);

	if (res)
		return BASE_ERR;

	res = ubus_invoke(ctx, id, "print_uptime", NULL,
						ubus_scal_upd_cb, cache, 500);
		
	if (res)
		return BASE_ERR;

	return BASE_OK;
}

static int ubus_scal_set(base_cache_t *cache, unsigned int subid, uint32_t index,
        unsigned int phase, const base_cell_t *cell)
{
    // (void)index;

    // switch (phase) {
    // case BASE_SET_RESERVE1:
	// 	return SNMP_ERR_NOERROR;

    // case BASE_SET_ACTION:
    //     if ((subid == SANDBOX_FIRST_SUBID_SCAL + COL_SANDBOX_STR) && (cell->asn_type == ASN_OCTET_STR)) {
    //         memcpy(sandbox_str, cell->data_str, BASE_STRLEN(cell->data_str));
    //         return SNMP_ERR_NOERROR;
    //     }
    //     return SNMP_ERR_WRONGTYPE;

    // case BASE_SET_COMMIT:
    //     base_cache_invalidate(cache);
    //     return SNMP_ERR_NOERROR;

    // case BASE_SET_UNDO:
    //     return SNMP_ERR_NOERROR;
    // }

    // return SNMP_ERR_GENERR;
}

void init_sandbox(void)
{
	if (base_ubus_init() != BASE_OK) {
        ERROR("dlmod sandbox: ubus init failed\n");
        return;
    }
        
    ctx = base_ubus_ctx();
    if (!ctx) {
        ERROR("dlmod sandbox: ubus ctx is NULL\n");
        base_ubus_deinit();
        return;
    }		

	base_cache_init(&sandbox_cache, SANDBOX_COL_COUNT_SCAL, SANDBOX_FIRST_SUBID_SCAL,
            BASE_CACHE_DYNAMIC, SANDBOX_CACHE_TTL, sandbox_update, sandbox_set);
	base_cache_init(&ubus_scal_cache, UBUS_COL_COUNT_SCAL, UBUS_FIRST_SUBID_SCAL,
		BASE_CACHE_DYNAMIC, UBUS_CACHE_TTL, ubus_scal_update, ubus_scal_set);

	if (base_register_scalars("sandbox_scal", &sandbox_cache, 
			sandbox_branch, OID_LENGTH(sandbox_branch)) != BASE_OK) {
		ERROR("dlmod sandbox: register sandbox_scal err\n");
		goto clean;
	}

	if (base_register_scalars("sandbox_ubus_scal", &ubus_scal_cache,
			sandbox_ubus_branch, OID_LENGTH(sandbox_ubus_branch)) != BASE_OK) {
		ERROR("dlmod sandbox: register sandbox_ubus_scal err\n");
		goto clean;
	}

	INFO("dlmod sandbox: init done\n");
	return;

clean:
	base_unregister_scalars(&sandbox_cache);
	base_unregister_scalars(&ubus_scal_cache);
	base_cache_deinit(&sandbox_cache);
	base_cache_deinit(&ubus_scal_cache);
	ctx = NULL;
	base_ubus_deinit();
	INFO("dlmod sandbox: clean done\n");
}

void deinit_sandbox(void)
{
	base_unregister_scalars(&sandbox_cache);
	base_unregister_scalars(&ubus_scal_cache);
	base_cache_deinit(&sandbox_cache);
	base_cache_deinit(&ubus_scal_cache);
	ctx = NULL;
	base_ubus_deinit();
	INFO("dlmod sandbox: deinit\n");
}