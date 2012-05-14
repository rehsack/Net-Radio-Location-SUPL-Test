/*
 * Generated by asn1c-0.9.23 (http://lionet.info/asn1c)
 * From ASN.1 module "RRLP-Components"
 * 	found in "../asn1src/RRLP-Components.asn"
 * 	`asn1c -gen-PER -fskeletons-copy -fnative-types`
 */

#include "AcquisElement.h"

static int
memb_doppler0_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -2048 && value <= 2047)) {
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
memb_codePhase_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 1022)) {
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
memb_intCodePhase_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 19)) {
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
memb_gpsBitNumber_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 3)) {
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
memb_codePhaseSearchWindow_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 15)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_doppler0_constr_3 = {
	{ APC_CONSTRAINED,	 12,  12, -2048,  2047 }	/* (-2048..2047) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_codePhase_constr_5 = {
	{ APC_CONSTRAINED,	 10,  10,  0,  1022 }	/* (0..1022) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_intCodePhase_constr_6 = {
	{ APC_CONSTRAINED,	 5,  5,  0,  19 }	/* (0..19) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_gpsBitNumber_constr_7 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_codePhaseSearchWindow_constr_8 = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_AcquisElement_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AcquisElement, svid),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SatelliteID,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"svid"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AcquisElement, doppler0),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_doppler0_constraint_1,
		&asn_PER_memb_doppler0_constr_3,
		0,
		"doppler0"
		},
	{ ATF_POINTER, 1, offsetof(struct AcquisElement, addionalDoppler),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AddionalDopplerFields,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"addionalDoppler"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AcquisElement, codePhase),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_codePhase_constraint_1,
		&asn_PER_memb_codePhase_constr_5,
		0,
		"codePhase"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AcquisElement, intCodePhase),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_intCodePhase_constraint_1,
		&asn_PER_memb_intCodePhase_constr_6,
		0,
		"intCodePhase"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AcquisElement, gpsBitNumber),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_gpsBitNumber_constraint_1,
		&asn_PER_memb_gpsBitNumber_constr_7,
		0,
		"gpsBitNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AcquisElement, codePhaseSearchWindow),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_codePhaseSearchWindow_constraint_1,
		&asn_PER_memb_codePhaseSearchWindow_constr_8,
		0,
		"codePhaseSearchWindow"
		},
	{ ATF_POINTER, 1, offsetof(struct AcquisElement, addionalAngle),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AddionalAngleFields,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"addionalAngle"
		},
};
static int asn_MAP_AcquisElement_oms_1[] = { 2, 7 };
static ber_tlv_tag_t asn_DEF_AcquisElement_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_AcquisElement_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* svid at 845 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* doppler0 at 849 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* addionalDoppler at 850 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* codePhase at 851 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* intCodePhase at 852 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* gpsBitNumber at 853 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* codePhaseSearchWindow at 854 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* addionalAngle at 855 */
};
static asn_SEQUENCE_specifics_t asn_SPC_AcquisElement_specs_1 = {
	sizeof(struct AcquisElement),
	offsetof(struct AcquisElement, _asn_ctx),
	asn_MAP_AcquisElement_tag2el_1,
	8,	/* Count of tags in the map */
	asn_MAP_AcquisElement_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_AcquisElement = {
	"AcquisElement",
	"AcquisElement",
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
	asn_DEF_AcquisElement_tags_1,
	sizeof(asn_DEF_AcquisElement_tags_1)
		/sizeof(asn_DEF_AcquisElement_tags_1[0]), /* 1 */
	asn_DEF_AcquisElement_tags_1,	/* Same as above */
	sizeof(asn_DEF_AcquisElement_tags_1)
		/sizeof(asn_DEF_AcquisElement_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_AcquisElement_1,
	8,	/* Elements count */
	&asn_SPC_AcquisElement_specs_1	/* Additional specs */
};

