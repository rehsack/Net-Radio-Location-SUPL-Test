/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "SUPL-INIT"
 * 	found in "../asn1src/SUPL-INIT.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "Notification.h"

static int
memb_requestorId_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size >= 1 && size <= 50)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_clientName_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size >= 1 && size <= 50)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_requestorId_constr_4 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 6,  6,  1,  50 }	/* (SIZE(1..50)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_clientName_constr_6 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 6,  6,  1,  50 }	/* (SIZE(1..50)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_Notification_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Notification, notificationType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NotificationType,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"notificationType"
		},
	{ ATF_POINTER, 5, offsetof(struct Notification, encodingType),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_EncodingType,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"encodingType"
		},
	{ ATF_POINTER, 4, offsetof(struct Notification, requestorId),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		memb_requestorId_constraint_1,
		&asn_PER_memb_requestorId_constr_4,
		0,
		"requestorId"
		},
	{ ATF_POINTER, 3, offsetof(struct Notification, requestorIdType),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FormatIndicator,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"requestorIdType"
		},
	{ ATF_POINTER, 2, offsetof(struct Notification, clientName),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		memb_clientName_constraint_1,
		&asn_PER_memb_clientName_constr_6,
		0,
		"clientName"
		},
	{ ATF_POINTER, 1, offsetof(struct Notification, clientNameType),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FormatIndicator,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"clientNameType"
		},
};
static int asn_MAP_Notification_oms_1[] = { 1, 2, 3, 4, 5 };
static ber_tlv_tag_t asn_DEF_Notification_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_Notification_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* notificationType at 20 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* encodingType at 21 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* requestorId at 22 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* requestorIdType at 23 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* clientName at 24 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* clientNameType at 25 */
};
static asn_SEQUENCE_specifics_t asn_SPC_Notification_specs_1 = {
	sizeof(struct Notification),
	offsetof(struct Notification, _asn_ctx),
	asn_MAP_Notification_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_Notification_oms_1,	/* Optional members */
	5, 0,	/* Root/Additions */
	5,	/* Start extensions */
	7	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Notification = {
	"Notification",
	"Notification",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_Notification_tags_1,
	sizeof(asn_DEF_Notification_tags_1)
		/sizeof(asn_DEF_Notification_tags_1[0]), /* 1 */
	asn_DEF_Notification_tags_1,	/* Same as above */
	sizeof(asn_DEF_Notification_tags_1)
		/sizeof(asn_DEF_Notification_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Notification_1,
	6,	/* Elements count */
	&asn_SPC_Notification_specs_1	/* Additional specs */
};

