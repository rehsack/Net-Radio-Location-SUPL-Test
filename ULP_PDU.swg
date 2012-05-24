%module ULP_PDU

%include "carrays.i"

%{
/* SUPL PDU */
#include "asn1/ULP-PDU.h"
%}

typedef struct ULP_PDU {
	long	 length;
	Version_t	 version;
	SessionID_t	 sessionID;
	UlpMessage_t	 message;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ULP_PDU_t;

typedef struct Version {
	long	 maj;
	long	 min;
	long	 servind;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Version_t;

typedef enum IPAddress_PR {
	IPAddress_PR_NOTHING,	/* No components present */
	IPAddress_PR_ipv4Address,
	IPAddress_PR_ipv6Address
} IPAddress_PR;

typedef struct IPAddress {
	IPAddress_PR present;
	union IPAddress_u {
		OCTET_STRING_t	 ipv4Address;
		OCTET_STRING_t	 ipv6Address;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IPAddress_t;

typedef enum SETId_PR {
	SETId_PR_NOTHING,	/* No components present */
	SETId_PR_msisdn,
	SETId_PR_mdn,
	SETId_PR_min,
	SETId_PR_imsi,
	SETId_PR_nai,
	SETId_PR_iPAddress,
	/* Extensions may appear below */
	
} SETId_PR;

typedef struct SETId {
	SETId_PR present;
	union SETId_u {
		OCTET_STRING_t	 msisdn;
		OCTET_STRING_t	 mdn;
		BIT_STRING_t	 min;
		OCTET_STRING_t	 imsi;
		IA5String_t	 nai;
		IPAddress_t	 iPAddress;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SETId_t;

typedef struct SetSessionID {
	long	 sessionId;
	SETId_t	 setId;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SetSessionID_t;

typedef enum SLPAddress_PR {
	SLPAddress_PR_NOTHING,	/* No components present */
	SLPAddress_PR_iPAddress,
	SLPAddress_PR_fQDN,
	/* Extensions may appear below */
	
} SLPAddress_PR;

typedef struct SLPAddress {
	SLPAddress_PR present;
	union SLPAddress_u {
		IPAddress_t	 iPAddress;
		FQDN_t	 fQDN;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SLPAddress_t;

typedef struct SlpSessionID {
	OCTET_STRING_t	 sessionID;
	SLPAddress_t	 slpId;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SlpSessionID_t;

typedef struct SessionID {
	struct SetSessionID	*setSessionID	/* OPTIONAL */;
	struct SlpSessionID	*slpSessionID	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SessionID_t;

typedef enum UlpMessage_PR {
	UlpMessage_PR_NOTHING,	/* No components present */
	UlpMessage_PR_msSUPLINIT,
	UlpMessage_PR_msSUPLSTART,
	UlpMessage_PR_msSUPLRESPONSE,
	UlpMessage_PR_msSUPLPOSINIT,
	UlpMessage_PR_msSUPLPOS,
	UlpMessage_PR_msSUPLEND,
	UlpMessage_PR_msSUPLAUTHREQ,
	UlpMessage_PR_msSUPLAUTHRESP,
	/* Extensions may appear below */
	
} UlpMessage_PR;

typedef struct UlpMessage {
	UlpMessage_PR present;
	union UlpMessage_u {
		SUPLINIT_t	 msSUPLINIT;
		SUPLSTART_t	 msSUPLSTART;
		SUPLRESPONSE_t	 msSUPLRESPONSE;
		SUPLPOSINIT_t	 msSUPLPOSINIT;
		SUPLPOS_t	 msSUPLPOS;
		SUPLEND_t	 msSUPLEND;
		SUPLAUTHREQ_t	 msSUPLAUTHREQ;
		SUPLAUTHRESP_t	 msSUPLAUTHRESP;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UlpMessage_t;

typedef enum PosMethod {
	PosMethod_agpsSETassisted	= 0,
	PosMethod_agpsSETbased	= 1,
	PosMethod_agpsSETassistedpref	= 2,
	PosMethod_agpsSETbasedpref	= 3,
	PosMethod_autonomousGPS	= 4,
	PosMethod_aFLT	= 5,
	PosMethod_eCID	= 6,
	PosMethod_eOTD	= 7,
	PosMethod_oTDOA	= 8,
	PosMethod_noPosition	= 9
	/*
	 * Enumeration is extensible
	 */
} e_PosMethod;

typedef long	 PosMethod_t;

typedef struct Notification {
	NotificationType_t	 notificationType;
	EncodingType_t	*encodingType	/* OPTIONAL */;
	OCTET_STRING_t	*requestorId	/* OPTIONAL */;
	FormatIndicator_t	*requestorIdType	/* OPTIONAL */;
	OCTET_STRING_t	*clientName	/* OPTIONAL */;
	FormatIndicator_t	*clientNameType	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Notification_t;

typedef struct QoP {
	long	 horacc;
	long	*veracc	/* OPTIONAL */;
	long	*maxLocAge	/* OPTIONAL */;
	long	*delay	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} QoP_t;

typedef enum SLPMode {
	SLPMode_proxy	= 0,
	SLPMode_nonProxy	= 1
} e_SLPMode;

typedef long	 SLPMode_t;

typedef BIT_STRING_t	 MAC_t;

typedef BIT_STRING_t	 KeyIdentity_t;

typedef struct SUPLINIT {
	PosMethod_t	 posMethod;
	struct Notification	*notification	/* OPTIONAL */;
	struct SLPAddress	*sLPAddress	/* OPTIONAL */;
	struct QoP	*qoP	/* OPTIONAL */;
	SLPMode_t	 sLPMode;
	MAC_t	*mAC	/* OPTIONAL */;
	KeyIdentity_t	*keyIdentity	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLINIT_t;

typedef struct SUPLSTART {
	SETCapabilities_t	 sETCapabilities;
	LocationId_t	 locationId;
	struct QoP	*qoP	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLSTART_t;

typedef struct SUPLRESPONSE {
	PosMethod_t	 posMethod;
	struct SLPAddress	*sLPAddress	/* OPTIONAL */;
	struct SETAuthKey	*sETAuthKey	/* OPTIONAL */;
	KeyIdentity4_t	*keyIdentity4	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLRESPONSE_t;

typedef struct SUPLPOSINIT {
	SETCapabilities_t	 sETCapabilities;
	struct RequestedAssistData	*requestedAssistData	/* OPTIONAL */;
	LocationId_t	 locationId;
	struct Position	*position	/* OPTIONAL */;
	struct SUPLPOS	*sUPLPOS	/* OPTIONAL */;
	Ver_t	*ver	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLPOSINIT_t;

typedef struct SUPLPOS {
	PosPayLoad_t	 posPayLoad;
	struct Velocity	*velocity	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLPOS_t;

typedef struct SUPLEND {
	struct Position	*position	/* OPTIONAL */;
	StatusCode_t	*statusCode	/* OPTIONAL */;
	Ver_t	*ver	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLEND_t;

typedef struct SUPLAUTHREQ {
	SETNonce_t	 sETNonce;
	KeyIdentity2_t	 keyIdentity2;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLAUTHREQ_t;

typedef struct SUPLAUTHRESP {
	struct SPCAuthKey	*sPCAuthKey	/* OPTIONAL */;
	KeyIdentity3_t	*keyIdentity3	/* OPTIONAL */;
	StatusCode_t	*statusCode	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SUPLAUTHRESP_t;

%{
typedef struct _MsgBuffer
{
	uint8_t *buf;
	ssize_t size;
} MsgBuffer;

struct per_target_buffer
{
	uint8_t *buf;
	size_t pos;
	size_t size;
};

static int
per_output(const void *data, size_t size, void *op_key)
{
	struct per_target_buffer *pb = op_key;
	if (pb->size < (pb->pos + size)) {
		uint8_t *tmp = realloc(pb->buf, pb->size + 4096);
		if (!tmp) {
			/* XXX report error */
			abort();
		}
		pb->buf = tmp;
		pb->size += 4096;
	}
	memcpy( pb->buf + pb->pos, data, size );
	pb->pos += size;

	return 0;
}

static const char *
asn_dec_rval_code_str(enum asn_dec_rval_code_e code)
{
    switch(code)
    {
    case RC_OK:
	return "RC_OK - Decoded successfully";

    case RC_WMORE:
	return "RC_WMORE - More data expected, call again";

    case RC_FAIL:
	return "RC_FAIL - Failure to decode data";

    default:
	return "Unknown decoder error code";
    }
}

static MsgBuffer
encode_ulp_pdu(struct ULP_PDU *pdu)
{
	/* asn_per_data_t per_data; */
	struct per_target_buffer per_buf;
	asn_enc_rval_t rval;
	MsgBuffer retbuf = { NULL, -1 };

	if (NULL == pdu)
		return retbuf;

	per_buf.buf = calloc( 4096, sizeof(uint8_t) );
	per_buf.pos = 0;
	per_buf.size = 4096;
	rval = uper_encode( &asn_DEF_ULP_PDU, pdu, &per_output, &per_buf);

	if (rval.encoded == -1) {
		free(per_buf.buf);
		croak("error encoding ULP pdu %s: %s",
			rval.failed_type->name,
			strerror(errno));

		return retbuf; /* unreached */
	}

	if (0 == pdu->length) {
		pdu->length = per_buf.pos;
		per_buf.pos = 0;

		/* encode 2nd with length set */
		rval = uper_encode( &asn_DEF_ULP_PDU, pdu, &per_output, &per_buf);
	}

#if 0
	xer_fprint(stdout, &asn_DEF_ULP_PDU, pdu);
	fflush(stdout);
#endif

	if (rval.encoded == -1) {
		free(per_buf.buf);
		croak("error encoding ULP pdu %s: %s",
			rval.failed_type->name,
			strerror(errno));

		return retbuf; /* unreached */
	}

	retbuf.buf = per_buf.buf;
	retbuf.size = per_buf.size;

	return retbuf;
}

static struct ULP_PDU *
decode_ulp_pdu(MsgBuffer buf)
{
	struct ULP_PDU *ulp_pdu = NULL;
	asn_dec_rval_t rval;
	asn_per_data_t per_data;

	per_data.buffer = buf.buf;
	per_data.nboff = 0;
	per_data.nbits = ((size_t)buf.size) * 8;
	rval = asn_DEF_ULP_PDU.uper_decoder( 0, &asn_DEF_ULP_PDU,
					NULL, (void **)&ulp_pdu,
					&per_data);
	if (rval.code != RC_OK) {
		/* Free partially decoded ulp-pdu */
		asn_DEF_ULP_PDU.free_struct(
			&asn_DEF_ULP_PDU, ulp_pdu, 0);

		croak("error parsing ULP pdu on byte %u with %s",
			(unsigned)rval.consumed,
			asn_dec_rval_code_str(rval.code));

		return NULL; /* unreached */
	}

#if 0
	xer_fprint(stdout, &asn_DEF_ULP_PDU, ulp_pdu);
#endif

	return ulp_pdu;
}

static MsgBuffer
ulp_pdu_to_xml(MsgBuffer buf)
{
	MsgBuffer retbuf = { NULL, -1 };
	asn_enc_rval_t rval;
	struct per_target_buffer per_buf;
	struct ULP_PDU *tmp_pdu = decode_ulp_pdu(buf);

	if (NULL == tmp_pdu)
		return retbuf;

	per_buf.buf = calloc( 4096, sizeof(uint8_t) );
	per_buf.pos = 0;
	per_buf.size = 4096;
	rval = xer_encode( &asn_DEF_ULP_PDU, tmp_pdu, XER_F_BASIC, &per_output, &per_buf);

	asn_DEF_ULP_PDU.free_struct(&asn_DEF_ULP_PDU, tmp_pdu, 0);

	if (rval.encoded == -1) {
		free(per_buf.buf);
		croak("error encoding ULP pdu %s: %s",
			rval.failed_type->name,
			strerror(errno));

		return retbuf; /* unreached */
	}

	retbuf.buf = per_buf.buf;
	retbuf.size = per_buf.size;

	return retbuf;
}
%}

%typemap(in) MsgBuffer {
    // $1 = AV2MsgBuf($input);
    // MsgBuffer retval = { NULL, -1 };
    if($input == NULL) {
	SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""'");
    }
    if( SvFLAGS($input) & (SVf_OK & ~SVf_ROK) ) {
	$1.buf = SvPV($input, $1.size);
    }
    else {
	SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$1_name" " of type '" "MsgBuffer""'");
    }
}

%typemap(newfree) MsgBuffer "do { if( $1.buf ) free($1.buf); } while(0);"
%typemap(newfree) MsgBuffer * "do { if( $1 ) { if( $1->buf ) { free( $1->buf ); } free( $1 ); } } while(0);"

%typemap(newfree) ULP_PDU_t * "asn_DEF_ULP_PDU.free_struct(&asn_DEF_ULP_PDU, $1, 0);"

%typemap(out) MsgBuffer {
#if 0
void      sv_setpvn(SV *, char *val, STRLEN len);
SV       *newSVpv(char *value, STRLEN len);
#endif
    $result = newSVpv($1.buf, $1.size);
    /* XXX This covers a bug */
    ++argvi;
}

%newobject encode_ulp_pdu;
%newobject ulp_pdu_to_xml;

MsgBuffer encode_ulp_pdu(struct ULP_PDU *pdu);
struct ULP_PDU *decode_ulp_pdu(MsgBuffer buf);
MsgBuffer ulp_pdu_to_xml(MsgBuffer buf);
