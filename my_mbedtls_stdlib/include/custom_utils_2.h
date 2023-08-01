#ifndef CUSTOM_UTILS_2_H
#define CUSTOM_UTILS_2_H
#include "custom_asn1.h"
#include "custom_utils.h"
#include "custom_oid.h"

// oid.c
/*
 * Macro to automatically add the size of #define'd OIDs
 */
#define ADD_LEN(s)      s, CUSTOM_OID_SIZE(s)

#define OID_DESCRIPTOR(s, name, description)  { ADD_LEN(s), name, description }
#define NULL_OID_DESCRIPTOR                   { NULL, 0, NULL, NULL }

/*
 * Macro to generate an internal function for oid_XXX_from_asn1() (used by
 * the other functions)
 */
#define FN_OID_TYPED_FROM_ASN1(TYPE_T, NAME, LIST)                    \
    static const TYPE_T *oid_ ## NAME ## _from_asn1(                   \
        const custom_asn1_buf *oid)     \
    {                                                                   \
        const TYPE_T *p = (LIST);                                       \
        const custom_oid_descriptor_t *cur =                           \
            (const custom_oid_descriptor_t *) p;                       \
        if (p == NULL || oid == NULL) return NULL;                  \
        while (cur->asn1 != NULL) {                                    \
            if (cur->asn1_len == oid->len &&                            \
                custom_memcmp(cur->asn1, oid->p, oid->len) == 0) {          \
                return p;                                            \
            }                                                           \
            p++;                                                        \
            cur = (const custom_oid_descriptor_t *) p;                 \
        }                                                               \
        return NULL;                                                 \
    }
    
/*
 * Macro to generate a function for retrieving a single attribute from an
 * custom_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
    int FN_NAME(const custom_asn1_buf *oid, ATTR1_TYPE * ATTR1)                  \
    {                                                                       \
        const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1(oid);        \
        if (data == NULL) return CUSTOM_ERR_OID_NOT_FOUND;            \
        *ATTR1 = data->ATTR1;                                               \
        return 0;                                                        \
    }

/*
 * Macro to generate a function for retrieving the OID based on two
 * attributes from a custom_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_OID_BY_ATTR2(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1,   \
                                ATTR2_TYPE, ATTR2)                          \
    int FN_NAME(ATTR1_TYPE ATTR1, ATTR2_TYPE ATTR2, const char **oid,         \
                size_t *olen)                                                 \
    {                                                                           \
        const TYPE_T *cur = (LIST);                                             \
        while (cur->descriptor.asn1 != NULL) {                                 \
            if (cur->ATTR1 == (ATTR1) && cur->ATTR2 == (ATTR2)) {              \
                *oid = cur->descriptor.asn1;                                    \
                *olen = cur->descriptor.asn1_len;                               \
                return 0;                                                    \
            }                                                                   \
            cur++;                                                              \
        }                                                                       \
        return CUSTOM_ERR_OID_NOT_FOUND;                                   \
    }
    
/*
 * For SignatureAlgorithmIdentifier
 */
typedef struct {
    custom_oid_descriptor_t    descriptor;
    custom_md_type_t           md_alg;
    custom_pk_type_t           pk_alg;
} oid_sig_alg_t;

extern const oid_sig_alg_t oid_sig_alg[];

int custom_oid_get_x509_ext_type(const custom_asn1_buf *oid, int *ext_type);
int custom_oid_get_oid_by_sig_alg(custom_pk_type_t pk_alg, custom_md_type_t md_alg, const char **oid, size_t *olen);

// hash_info.c
unsigned char custom_hash_info_get_size(custom_md_type_t md_type);

#endif
