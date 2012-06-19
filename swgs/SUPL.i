// mapping has to be done before 1st struct/class defined which uses it ...

%typemap(in) SatelliteInfo_t * {
    AV *tempav;
    I32 len;
    int i;
    SV  **tv;

    /* verify input type */
    if(!SvROK($input))
	croak("Argument $argnum is not a reference.");
    if(SvTYPE(SvRV($input)) != SVt_PVAV)
	croak("Argument $argnum is not an array.");

    $1 = calloc(1, sizeof(*$1));

    tempav = (AV *)SvRV($input);
    $1->list.count = $1->list.size = av_len(tempav);
    /* $1->list.free = asn_DEF_SatelliteInfoElement. ??? */
    $1->list.array = calloc($1->list.size, sizeof(*$1->list.array));

    for (i = 0; i <= $1->list.size; ++i) {
	AV *inner_av;
	SV **inner_iv;

	tv = av_fetch(tempav, i, 0);	
	if(NULL == tv) {
	    asn_DEF_SatelliteInfo.free_struct(&asn_DEF_SatelliteInfo, $1, 0);
	    croak( "Couldn't fetch element at position %d", i );
	}

	if(SvTYPE(SvRV(*tv)) != SVt_PVAV) {
	    asn_DEF_SatelliteInfo.free_struct(&asn_DEF_SatelliteInfo, $1, 0);
	    croak("Element at position %d is not an array", i);
	}

	$1->list.array[i] = calloc(1, sizeof(*$1->list.array[i]));
	if(NULL == $1->list.array[i]) {
	    asn_DEF_SatelliteInfo.free_struct(&asn_DEF_SatelliteInfo, $1, 0);
	    croak("Couldn't allocate memory to transform element at %d position into SatelliteInfoElement", i);
	}

	inner_av = (AV *)SvRV(*tv);

	inner_iv = av_fetch(inner_av, 0, 0);
	if(NULL == inner_iv) {
	    asn_DEF_SatelliteInfo.free_struct(&asn_DEF_SatelliteInfo, $1, 0);
	    croak( "Couldn't fetch satId from element at position %d", i );
	}
	$1->list.array[i]->satId = SvIV(*inner_iv);

	inner_iv = av_fetch(inner_av, 1, 0);
	if(NULL == inner_iv) {
	    asn_DEF_SatelliteInfo.free_struct(&asn_DEF_SatelliteInfo, $1, 0);
	    croak( "Couldn't fetch iODE from element at position %d", i );
	}
	$1->list.array[i]->iODE = SvIV(*inner_iv);
    }
}

%typemap(in) IPAddress_t {
    if( 0 == (SvFLAGS($input) & (SVf_OK & ~SVf_ROK)) )
	croak("Argument $argnum is not an embedded ip address.");
    if( SvLEN($input) == 4 ) {
	// IPv4
	$1.present = IPAddress_PR_ipv4Address;
	OCTET_STRING_fromBuf(&$1.choice.ipv4Address, SvPV_nolen($input), 4);
    }
    else if( SvLEN($input) == 16 ) {
	// IPv6
	$1.present = IPAddress_PR_ipv6Address;
	OCTET_STRING_fromBuf(&$1.choice.ipv6Address, SvPV_nolen($input), 16);
    }
    else
	croak("Argument $argnum is not an embedded ip address.");
}

%typemap(out) IPAddress_t {
    if (argvi >= items) {
	EXTEND(sp,1); /* Extend the stack by 1 object */
    }
    $result = sv_newmortal();
    if(IPAddress_PR_ipv4Address == $1.present && 4 == $1.choice.ipv4Address.size) {
	sv_setpvn($result, (char *)($1.choice.ipv4Address.buf), 4);
    }
    else if(IPAddress_PR_ipv6Address == $1.present && 16 == $1.choice.ipv4Address.size) {
	sv_setpvn($result, (char *)($1.choice.ipv6Address.buf), 16);
    }
    ++argvi; /* intentional - not portable between languages */
}

%typemap(out) IPAddress_t * {
    if (argvi >= items) {
	EXTEND(sp,1); /* Extend the stack by 1 object */
    }
    $result = sv_newmortal();
    if(IPAddress_PR_ipv4Address == $1->present && 4 == $1->choice.ipv4Address.size) {
	sv_setpvn($result, (char *)($1->choice.ipv4Address.buf), 4);
    }
    else if(IPAddress_PR_ipv6Address == $1->present && 16 == $1->choice.ipv4Address.size) {
	sv_setpvn($result, (char *)($1->choice.ipv6Address.buf), 16);
    }
    ++argvi; /* intentional - not portable between languages */
}

%typemap(newfree) IPAddress_t "asn_DEF_IPAddress.free_struct(&asn_DEF_IPAddress, &$1, 1);"
%typemap(newfree) IPAddress_t * "if( $1 ) { asn_DEF_IPAddress.free_struct(&asn_DEF_IPAddress, $1, 0); }"

%apply OCTET_STRING_t { MAC_t, FQDN_t, KeyIdentity_t, Ver_t };

%include "asn1/SUPLAUTHREQ.h"
%include "asn1/SUPLAUTHRESP.h"
%include "asn1/SUPLEND.h"
%include "asn1/SUPLINIT.h"
%include "asn1/SUPLPOS.h"
%include "asn1/SUPLPOSINIT.h"
%include "asn1/SUPLRESPONSE.h"
%include "asn1/SUPLSTART.h"
%include "asn1/ULP-PDU.h"
%include "asn1/UlpMessage.h"

// helper classes
%include "asn1/SLPAddress.h"

enum PrefMethod {
	PrefMethod_agpsSETassistedPreferred = 0,
	PrefMethod_agpsSETBasedPreferred = 1,
	PrefMethod_noPreference = 2
};
typedef long PrefMethod_t;

enum SLPMode {
	SLPMode_proxy	= 0,
	SLPMode_nonProxy	= 1
};

typedef long SLPMode_t;

enum Status {
	Status_stale	= 0,
	Status_current	= 1,
	Status_unknown	= 2
	/*
	 * Enumeration is extensible
	 */
};

typedef long Status_t;

%extend ULP_PDU {
    ULP_PDU() {
	ULP_PDU_t *newobj;
	newobj = calloc( 1, sizeof(*newobj) );
	if( NULL == newobj )
	    croak( "Can't allocate memory for new ULP_PDU object" );

	newobj->version.maj = 1;
	newobj->version.min = 0;
	newobj->version.servind = 0;
	return newobj;
    }

    ~ULP_PDU() {
	asn_DEF_ULP_PDU.free_struct(&asn_DEF_ULP_PDU, $self, 0);
    }

    void set_version(int maj, int min, int servind) {
	if( maj == 1 && min == 0 && servind == 0 ) {
	    self->version.maj = maj;
	    self->version.min = min;
	    self->version.servind = servind;
	}
	else {
	    croak( "Unsupported SUPL version" );
	}
    }

    void setSetSessionId_to_imsi(int sessionId, char *imsi) {
	if( NULL != $self->sessionID.setSessionID ) {
	    asn_DEF_SetSessionID.free_struct(&asn_DEF_SetSessionID, $self->sessionID.setSessionID, 0);
	    $self->sessionID.setSessionID = NULL;
	}
	$self->sessionID.setSessionID = calloc(1, sizeof(*($self->sessionID.setSessionID)));
	$self->sessionID.setSessionID->setId.present = SETId_PR_imsi;
	BCD_OCTET_STRING_fromString(&$self->sessionID.setSessionID->setId.choice.imsi, imsi);
    }

    void setSetSessionId_to_msisdn(int sessionId, char *msisdn) {
	if( NULL != $self->sessionID.setSessionID ) {
	    asn_DEF_SetSessionID.free_struct(&asn_DEF_SetSessionID, $self->sessionID.setSessionID, 0);
	    $self->sessionID.setSessionID = NULL;
	}
	$self->sessionID.setSessionID = calloc(1, sizeof(*($self->sessionID.setSessionID)));
	$self->sessionID.setSessionID->setId.present = SETId_PR_msisdn;
	BCD_OCTET_STRING_fromString(&$self->sessionID.setSessionID->setId.choice.msisdn, msisdn);
    }

    void copy_SlpSessionId(ULP_PDU_t *src_pdu) {
	struct SlpSessionID *src, *dst;
	OCTET_STRING_t *srcaddr;
	OCTET_STRING_t *dstaddr;

	src = src_pdu->sessionID.slpSessionID;

	if( NULL == src )
	    return; /* nothing to do */

	if( NULL != $self->sessionID.slpSessionID ) {
	    asn_DEF_SlpSessionID.free_struct(&asn_DEF_SlpSessionID, $self->sessionID.slpSessionID, 0);
	    $self->sessionID.slpSessionID = NULL;
	}

	$self->sessionID.slpSessionID = calloc(1, sizeof(*($self->sessionID.slpSessionID)));
	dst = $self->sessionID.slpSessionID;

	OCTET_STRING_fromBuf(&dst->sessionID, src->sessionID.buf, src->sessionID.size);
	switch (src->slpId.present)
	{
	case SLPAddress_PR_iPAddress:
	    dst->slpId.present = SLPAddress_PR_iPAddress;
	    switch (src->slpId.choice.iPAddress.present)
	    {
	    case IPAddress_PR_ipv4Address:
		dst->slpId.choice.iPAddress.present = IPAddress_PR_ipv4Address;
		srcaddr = &src->slpId.choice.iPAddress.choice.ipv4Address;
		dstaddr = &dst->slpId.choice.iPAddress.choice.ipv4Address;

		break;

	    case IPAddress_PR_ipv6Address:
		dst->slpId.choice.iPAddress.present = IPAddress_PR_ipv6Address;
		srcaddr = &src->slpId.choice.iPAddress.choice.ipv6Address;
		dstaddr = &dst->slpId.choice.iPAddress.choice.ipv6Address;

		break;

	    default:
		dst->slpId.choice.iPAddress.present = IPAddress_PR_NOTHING;
		croak("Invalid: source has slpSessionId but neither IP-Address nor FQDN content");

		break;
	    }

	    break;

	case SLPAddress_PR_fQDN:
	    dst->slpId.present = SLPAddress_PR_fQDN;
	    srcaddr = &src->slpId.choice.fQDN;
	    dstaddr = &dst->slpId.choice.fQDN;

	    break;

	default:
	    /* error */
	    dst->slpId.present = SLPAddress_PR_NOTHING;
	    croak("Invalid: source has slpSessionId but neither IP-Address nor FQDN content");

	    break;
	}
	OCTET_STRING_fromBuf(dstaddr, srcaddr->buf, srcaddr->size);
    }

    void set_message_type(UlpMessage_PR kinda) {
	if($self->message.present != UlpMessage_PR_NOTHING) {
	    asn_DEF_UlpMessage.free_struct(&asn_DEF_UlpMessage, &$self->message, 1);
	    memset(&$self->message, 0, sizeof($self->message));
	}

	switch(kinda) {
	case UlpMessage_PR_msSUPLINIT:
	    break;

	case UlpMessage_PR_msSUPLSTART:
	    break;

	case UlpMessage_PR_msSUPLRESPONSE:
	    break;

	case UlpMessage_PR_msSUPLPOSINIT:
	    break;

	case UlpMessage_PR_msSUPLPOS:
	    break;

	case UlpMessage_PR_msSUPLEND:
	    break;

	case UlpMessage_PR_msSUPLAUTHREQ:
	    break;

	case UlpMessage_PR_msSUPLAUTHRESP:
	    break;

	default:
	    croak("Invalid value for message type %d, expecting between %d .. %d",
		    (int)kinda,
		    (int)UlpMessage_PR_msSUPLINIT,
		    (int)UlpMessage_PR_msSUPLAUTHRESP);

	    break;
	}

	$self->message.present = kinda;
    }

    %newobject encode;
    MsgBuffer encode() {
	return encode_ulp_pdu($self);
    }

    %newobject dump;
    char * dump() {
	struct per_target_buffer per_buf = { calloc( 4096, sizeof(*per_buf.buf) ), 0, 4096 };

	asn_DEF_ULP_PDU.print_struct(&asn_DEF_ULP_PDU, $self, 4, &per_output, &per_buf);

	return (char *)per_buf.buf;
    }

    %newobject xml_dump;
    char * xml_dump() {
	asn_enc_rval_t rval;
	struct per_target_buffer per_buf = { calloc( 4096, sizeof(*per_buf.buf) ), 0, 4096 };

	rval = xer_encode( &asn_DEF_ULP_PDU, $self, XER_F_BASIC, &per_output, &per_buf);

	return (char *)per_buf.buf;
    }
};

%nodefaultctor SUPLINIT;
%extend SUPLINIT {
    ~SUPLINIT() {
	asn_DEF_SUPLINIT.free_struct(&asn_DEF_SUPLINIT, $self, 1);
    }

    ;
};

%nodefaultctor SUPLSTART;
%extend SUPLSTART {
    ~SUPLSTART() {
	asn_DEF_SUPLSTART.free_struct(&asn_DEF_SUPLSTART, $self, 1);
    }
};

%nodefaultctor SUPLRESPONSE;
%extend SUPLRESPONSE {
    ~SUPLRESPONSE() {
	asn_DEF_SUPLRESPONSE.free_struct(&asn_DEF_SUPLRESPONSE, $self, 1);
    }
};

%nodefaultctor SUPLPOSINIT;
%extend SUPLPOSINIT {

#define setcap_pos_tech_agpsSETassisted (1 << 0)
#define setcap_pos_tech_agpsSETBased (2 << 0)
#define setcap_pos_tech_autonomousGPS (3 << 0)
#define setcap_pos_tech_aFLT (4 << 0)
#define setcap_pos_tech_eCID (5 << 0)
#define setcap_pos_tech_eOTD (6 << 0)
#define setcap_pos_tech_oTDOA (7 << 0)

#define setcap_pos_proto_tia801 (1 << 0)
#define setcap_pos_proto_rrlp (1 << 1)
#define setcap_pos_proto_rrc (1 << 2)

#define reqassistdata_almanacRequested (1 << 0)
#define reqassistdata_utcModelRequested (1 << 1)
#define reqassistdata_ionosphericModelRequested (1 << 2)
#define reqassistdata_dgpsCorrectionsRequested (1 << 3)
#define reqassistdata_referenceLocationRequested (1 << 4)
#define reqassistdata_referenceTimeRequested (1 << 5)
#define reqassistdata_acquisitionAssistanceRequested (1 << 6)
#define reqassistdata_realTimeIntegrityRequested (1 << 7)
//#define reqassistdata_navigationModelRequested (1 << 8)

    ~SUPLPOSINIT() {
	asn_DEF_SUPLPOSINIT.free_struct(&asn_DEF_SUPLPOSINIT, $self, 1);
    }

    void set_capabilities(unsigned int pos_tech, enum PrefMethod pref_method, unsigned int pos_proto) {
	$self->sETCapabilities.posTechnology.agpsSETassisted = pos_tech & setcap_pos_tech_agpsSETassisted ? 1 : 0;
	$self->sETCapabilities.posTechnology.agpsSETBased = pos_tech & setcap_pos_tech_agpsSETBased ? 1 : 0;
	$self->sETCapabilities.posTechnology.autonomousGPS = pos_tech & setcap_pos_tech_autonomousGPS ? 1 : 0;
	$self->sETCapabilities.posTechnology.aFLT = pos_tech & setcap_pos_tech_aFLT ? 1 : 0;
	$self->sETCapabilities.posTechnology.eCID = pos_tech & setcap_pos_tech_eCID ? 1 : 0;
	$self->sETCapabilities.posTechnology.eOTD = pos_tech & setcap_pos_tech_eOTD ? 1 : 0;
	$self->sETCapabilities.posTechnology.oTDOA = pos_tech & setcap_pos_tech_oTDOA ? 1 : 0;

	$self->sETCapabilities.prefMethod = pref_method;

	$self->sETCapabilities.posProtocol.tia801 = pos_proto & setcap_pos_proto_tia801 ? 1 : 0;
	$self->sETCapabilities.posProtocol.rrlp = pos_proto & setcap_pos_proto_rrlp ? 1 : 0;
	$self->sETCapabilities.posProtocol.rrc = pos_proto & setcap_pos_proto_rrc ? 1 : 0;
    }

    void set_requested_assist_data(unsigned int requested_assist_data) {
	if($self->requestedAssistData != NULL) {
	    asn_DEF_RequestedAssistData.free_struct(&asn_DEF_RequestedAssistData, &$self->requestedAssistData, 0);
	    $self->requestedAssistData = NULL;
	}

	$self->requestedAssistData = calloc(1, sizeof(*($self->requestedAssistData)));
	if( NULL == $self->requestedAssistData )
	    croak( "Can't allocate memory for new RequestedAssistData object" );

	$self->requestedAssistData->almanacRequested = requested_assist_data & reqassistdata_almanacRequested ? 1 : 0;
	$self->requestedAssistData->utcModelRequested = requested_assist_data & reqassistdata_utcModelRequested ? 1 : 0;
	$self->requestedAssistData->ionosphericModelRequested = requested_assist_data & reqassistdata_ionosphericModelRequested ? 1 : 0;
	$self->requestedAssistData->dgpsCorrectionsRequested = requested_assist_data & reqassistdata_dgpsCorrectionsRequested ? 1 : 0;
	$self->requestedAssistData->referenceLocationRequested = requested_assist_data & reqassistdata_referenceLocationRequested ? 1 : 0;
	$self->requestedAssistData->referenceTimeRequested = requested_assist_data & reqassistdata_referenceTimeRequested ? 1 : 0;
	$self->requestedAssistData->acquisitionAssistanceRequested = requested_assist_data & reqassistdata_acquisitionAssistanceRequested ? 1 : 0;
	$self->requestedAssistData->realTimeIntegrityRequested = requested_assist_data & reqassistdata_realTimeIntegrityRequested ? 1 : 0;
	$self->requestedAssistData->navigationModelRequested = 0;
    }

    void update_requested_assist_data(unsigned int requested_assist_data) {
	if( NULL == $self->requestedAssistData )
	    SUPLPOSINIT_set_requested_assist_data($self, requested_assist_data);
	else {
	    $self->requestedAssistData->almanacRequested = requested_assist_data & reqassistdata_almanacRequested ? 1 : 0;
	    $self->requestedAssistData->utcModelRequested = requested_assist_data & reqassistdata_utcModelRequested ? 1 : 0;
	    $self->requestedAssistData->ionosphericModelRequested = requested_assist_data & reqassistdata_ionosphericModelRequested ? 1 : 0;
	    $self->requestedAssistData->dgpsCorrectionsRequested = requested_assist_data & reqassistdata_dgpsCorrectionsRequested ? 1 : 0;
	    $self->requestedAssistData->referenceLocationRequested = requested_assist_data & reqassistdata_referenceLocationRequested ? 1 : 0;
	    $self->requestedAssistData->referenceTimeRequested = requested_assist_data & reqassistdata_referenceTimeRequested ? 1 : 0;
	    $self->requestedAssistData->acquisitionAssistanceRequested = requested_assist_data & reqassistdata_acquisitionAssistanceRequested ? 1 : 0;
	    $self->requestedAssistData->realTimeIntegrityRequested = requested_assist_data & reqassistdata_realTimeIntegrityRequested ? 1 : 0;
	}
    }

    void set_requested_assist_navigation_modell(long gpsWeek, long gpsToe, long nSAT, long toeLimit, SatelliteInfo_t * sat_info) {
	if( NULL == $self->requestedAssistData )
	    SUPLPOSINIT_set_requested_assist_data($self, 0);

	$self->requestedAssistData->navigationModelRequested = 1;
	if($self->requestedAssistData->navigationModelData != NULL) {
	    asn_DEF_NavigationModel.free_struct(&asn_DEF_NavigationModel, &$self->requestedAssistData->navigationModelData, 0);
	    $self->requestedAssistData->navigationModelData = NULL;
	}

	$self->requestedAssistData->navigationModelData = calloc(1, sizeof(*($self->requestedAssistData->navigationModelData)));
	if( NULL == $self->requestedAssistData->navigationModelData )
	    croak( "Can't allocate memory for new NavigationModel object" );

	$self->requestedAssistData->navigationModelData->gpsWeek = gpsWeek;
	$self->requestedAssistData->navigationModelData->gpsToe = gpsToe;
	$self->requestedAssistData->navigationModelData->nSAT = nSAT;
	$self->requestedAssistData->navigationModelData->toeLimit = toeLimit;
	$self->requestedAssistData->navigationModelData->satInfo = sat_info;
    }

    void set_gsm_location_info(long mcc, long mnc, long lac, long cellid, long ta) {
	LocationId_t *dst = &$self->locationId;

	dst->cellInfo.present = CellInfo_PR_gsmCell;
	dst->cellInfo.choice.gsmCell.refMCC = mcc;
	dst->cellInfo.choice.gsmCell.refMNC = mnc;
	dst->cellInfo.choice.gsmCell.refLAC = lac;
	dst->cellInfo.choice.gsmCell.refCI = cellid;
	dst->cellInfo.choice.gsmCell.tA = calloc(1, sizeof(*(dst->cellInfo.choice.gsmCell.tA)));
	dst->cellInfo.choice.gsmCell.tA[0] = ta;
    }

    void set_position_estimate( time_t when, long latitudeSign, long latitude, long longitude ) {
	struct tm *gm_when;

	gm_when = gmtime(&when);
	asn_time2UT(&$self->position->timestamp, gm_when, 1);
	$self->position->positionEstimate.latitudeSign = latitudeSign;
	$self->position->positionEstimate.latitude = latitude;
	$self->position->positionEstimate.longitude = longitude;
    }

    // void set_position_velocity(...)
};

%nodefaultctor SUPLPOS;
%extend SUPLPOS {
    ~SUPLPOS() {
	asn_DEF_SUPLPOS.free_struct(&asn_DEF_SUPLPOS, $self, 1);
    }
};

%nodefaultctor SUPLEND;
%extend SUPLEND {
    ~SUPLEND() {
	asn_DEF_SUPLEND.free_struct(&asn_DEF_SUPLEND, $self, 1);
    }
};

%nodefaultctor SUPLAUTHREQ;
%extend SUPLAUTHREQ {
    ~SUPLAUTHREQ() {
	asn_DEF_SUPLAUTHREQ.free_struct(&asn_DEF_SUPLAUTHREQ, $self, 1);
    }
};

%nodefaultctor SUPLAUTHREQ;
%extend SUPLAUTHRESP {
    ~SUPLAUTHRESP() {
	asn_DEF_SUPLAUTHRESP.free_struct(&asn_DEF_SUPLAUTHRESP, $self, 1);
    }
};

%nodefaultctor SLPAddress;
%extend SLPAddress {
    ~SLPAddress() {
	asn_DEF_SLPAddress.free_struct(&asn_DEF_SLPAddress, $self, 1);
    }

    void set_ipaddress(IPAddress_t ipaddr) {
	$self->present = SLPAddress_PR_iPAddress;
	$self->choice.iPAddress = ipaddr;
    }

    void set_fqdn(const char *buf) {
	$self->present = SLPAddress_PR_fQDN;
	OCTET_STRING_fromString(&$self->choice.fQDN, buf);
    }

    int is_ipv4() {
	return ($self->present == SLPAddress_PR_iPAddress) &&
	       ((($self->choice.iPAddress.present == IPAddress_PR_ipv4Address) && 
	         ($self->choice.iPAddress.choice.ipv4Address.size == 4)));
    }

    int is_ipv6() {
	return ($self->present == SLPAddress_PR_iPAddress) &&
	       ((($self->choice.iPAddress.present == IPAddress_PR_ipv6Address) && 
	         ($self->choice.iPAddress.choice.ipv6Address.size == 16)));
    }

    int is_ip() {
	return SLPAddress_is_ipv4($self) || SLPAddress_is_ipv6($self);
    }

    int is_fqdn() {
	return ($self->present == SLPAddress_PR_iPAddress) &&
	       ($self->choice.fQDN.size > 0 && $self->choice.fQDN.buf != NULL);
    }

    int is_valid() {
	return SLPAddress_is_ip($self) || SLPAddress_is_fqdn($self);
    }
};
