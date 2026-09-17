#include <base.h>
#include <base_parse.h>

#include "sandbox.h"

#define SANDBOX_LOG_TAG "sandbox.so >> "

#define SANDBOX_ERROR(_text_, ...) ERROR(SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)
#define SANDBOX_INFO(_text_, ...) INFO(SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)
#define SANDBOX_DEBUG(_condition_, _text_, ...) DEBUG(_condition_, SANDBOX_LOG_TAG _text_, ##__VA_ARGS__)

#define SANDBOX_FIRST_SUBID_SCAL 1
#define SANDBOX_COL_COUNT_SCAL 2

#define SANDBOX_CACHE_TTL 	5

enum {
    COL_REQ_CNT,
    COL_SANDBOX_STR,
    COL_NUM
};

base_cache_t sandbox_cache;

int32_t req_cnt = 0;
char sandbox_str[64] = { 0 };

// ====[local data - scalars]====
/* sandbox: 1.3.6.1.4.1.60641.1.5.1 - ro request_counter integer32, [src - sandbox.so]*/
/* sandbox: 1.3.6.1.4.1.60641.1.5.2 - rw sandbox_string octet str [64], [src - sandbox.so]*/

static oid sandbox_branch[] = { 1, 3, 6, 1, 4, 1, 60641, 1, 5};

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

void init_sandbox(void)
{ 
	base_cache_init(&sandbox_cache, SANDBOX_COL_COUNT_SCAL, SANDBOX_FIRST_SUBID_SCAL,
            BASE_CACHE_DYNAMIC, SANDBOX_CACHE_TTL, sandbox_update, sandbox_set);

	if (base_register_scalars("sandbox_scal", &sandbox_cache, 
			sandbox_branch, OID_LENGTH(sandbox_branch)) != BASE_OK) {
		SANDBOX_ERROR("register sandbox_scal err\n");
		goto clean;
	}

	SANDBOX_INFO("init done\n");
	return;

clean:
	base_unregister_scalars(&sandbox_cache);
	base_cache_deinit(&sandbox_cache);
	SANDBOX_INFO("clean done\n");
}

void deinit_sandbox(void)
{
	base_unregister_scalars(&sandbox_cache);
	base_cache_deinit(&sandbox_cache);
	SANDBOX_INFO("deinit\n");
}