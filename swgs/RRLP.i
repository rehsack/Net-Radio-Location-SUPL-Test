%typemap(arginit) AccuracyOpt_t {
    memset(&$1, 0, sizeof($1));
}

%typemap(in) AccuracyOpt_t {
    if( 0 != SvOK($input) ) {
	$1.accuracy = calloc(1, sizeof(*($1.accuracy)));
	if( $1.accuracy ) {
	    *($1.accuracy) = SvIV($input);
	}
	else {
	    asn_DEF_AccuracyOpt.free_struct(&asn_DEF_AccuracyOpt, $input, 0);
	    croak("Couldn't allocate memory to transform Accuracy_t embedded attribute of AccuracyOpt_t at $argnum");
	}
    }
    else {
	$1.accuracy = NULL;
    }
}

%typemap(in) AccuracyOpt_t * {
    $1 = calloc(1, sizeof(*$1));
    if( $1 ) {
	if( 0 != SvOK($input) ) {
	    $1->accuracy = calloc(1, sizeof(*($1->accuracy)));
	    if( $1->accuracy ) {
		*($1->accuracy) = SvIV($input);
	    }
	    else {
		asn_DEF_AccuracyOpt.free_struct(&asn_DEF_AccuracyOpt, $input, 0);
		croak("Couldn't allocate memory to transform Accuracy_t embedded attribute of AccuracyOpt_t at $argnum");
	    }
	}
	else {
	    $1->accuracy = NULL;
	}
    }
    else {
	croak("Couldn't allocate memory to transform AccuracyOpt_t at $argnum", i);
    }
}

%typemap(out) AccuracyOpt_t {
    if (argvi >= items) {
	EXTEND(sp,1); /* Extend the stack by 1 object */
    }
    $result = sv_newmortal();
    if(NULL != $1.accuracy) {
	sv_setiv($result, *($1.accuracy));
    }
    ++argvi; /* intentional - not portable between languages */
}

%typemap(out) AccuracyOpt_t * {
    if (argvi >= items) {
	EXTEND(sp,1); /* Extend the stack by 1 object */
    }
    $result = sv_newmortal();
    if($1 && $1->accuracy) {
	sv_setiv($result, *($1->accuracy));
    }
    ++argvi; /* intentional - not portable between languages */
}

%typemap(newfree) AccuracyOpt_t "asn_DEF_AccuracyOpt.free_struct(&asn_DEF_AccuracyOpt, &$1, 1);"
%typemap(newfree) AccuracyOpt_t * "if( $1 ) { asn_DEF_AccuracyOpt.free_struct(&asn_DEF_AccuracyOpt, $1, 0); }"

%apply OCTET_STRING_t { VelocityEstimate_t };
%apply OCTET_STRING_t * { VelocityEstimate_t * };

%ignore asn_DEF_RRLP_Component;
%ignore asn_DEF_MsrPosition_Req;
%ignore asn_DEF_MsrPosition_Rsp;
%ignore asn_DEF_PositionInstruct;
%ignore asn_DEF_MethodType;
%ignore asn_DEF_RRLP_PDU;

%include "asn1/RRLP-PDU.h"
%include "asn1/RRLP-Component.h"
%include "asn1/MsrPosition-Req.h"
%include "asn1/MsrPosition-Rsp.h"
%include "asn1/PositionInstruct.h"
%include "asn1/MethodType.h"
%include "asn1/ProtocolError.h"
typedef long Accuracy_t;
typedef long ErrorCodes_t;

%extend RRLP_PDU {
    RRLP_PDU() {
	struct RRLP_PDU *newobj;
        newobj = calloc( 1, sizeof(*newobj) );
        if( NULL == newobj )
            croak( "Can't allocate memory for new RRLP_PDU object" );

        return newobj;
    }

    RRLP_PDU(const char *data, size_t data_len) {
	struct RRLP_PDU *newobj = NULL;
        asn_dec_rval_t rval;
        asn_per_data_t per_data = { data, 0, data_len * 8 };

        rval = asn_DEF_RRLP_PDU.uper_decoder( 0, &asn_DEF_RRLP_PDU,
                                        NULL, (void **)&newobj,
                                        &per_data);
        if (rval.code != RC_OK) {
                /* Free partially decoded rrlp */
                asn_DEF_RRLP_PDU.free_struct(
                        &asn_DEF_RRLP_PDU, newobj, 0);

                croak("error parsing RRLP pdu on byte %u with %s",
                        (unsigned)rval.consumed,
                        asn_dec_rval_code_str(rval.code));

                return NULL; /* unreached */
        }

        return newobj;
    }

    ~RRLP_PDU() {
	asn_DEF_RRLP_PDU.free_struct(&asn_DEF_RRLP_PDU, $self, 1);
    }

    %newobject encode;
    MsgBuffer encode() {
	/* asn_per_data_t per_data; */
	struct per_target_buffer per_buf;
	asn_enc_rval_t rval = { 0 };
	MsgBuffer retbuf = { NULL, -1 };

	per_buf.buf = calloc( 4096, sizeof(uint8_t) );
	per_buf.pos = 0;
	per_buf.size = 4096;
	rval = uper_encode(&asn_DEF_RRLP_PDU, $self, &per_output, &per_buf);

	if (rval.encoded == -1) {
		free(per_buf.buf);
		croak("error encoding RRLP pdu %s: %s",
			rval.failed_type->name,
			strerror(errno));

		return retbuf; /* unreached */
	}

	retbuf.buf = per_buf.buf;
	retbuf.size = per_buf.pos;

	return retbuf;
    }

    %newobject dump;
    char * dump() {
	struct per_target_buffer per_buf = { calloc( 4096, sizeof(*per_buf.buf) ), 0, 4096 };

	asn_DEF_RRLP_PDU.print_struct(&asn_DEF_RRLP_PDU, $self, 4, &per_output, &per_buf);

	return (char *)per_buf.buf;
    }

    %newobject xml_dump;
    char * xml_dump() {
	asn_enc_rval_t rval = { 0 };
	struct per_target_buffer per_buf = { calloc( 4096, sizeof(*per_buf.buf) ), 0, 4096 };

	rval = xer_encode( &asn_DEF_RRLP_PDU, $self, XER_F_BASIC, &per_output, &per_buf);

	return (char *)per_buf.buf;
    }

    void set_component_type(RRLP_Component_PR kind_of)
    {
	if($self->component.present != RRLP_Component_PR_NOTHING) {
	    asn_DEF_RRLP_PDU.free_struct(&asn_DEF_RRLP_PDU, &$self->component, 1);
	    memset(&$self->component, 0, sizeof($self->component));
	}

        switch(kind_of)
        {
        case RRLP_Component_PR_msrPositionReq:
            break;
        case RRLP_Component_PR_msrPositionRsp:
            break;
        case RRLP_Component_PR_assistanceData:
            break;
        case RRLP_Component_PR_assistanceDataAck:
            break;
        case RRLP_Component_PR_protocolError:
            break;
        case RRLP_Component_PR_posCapabilityReq:
            break;
        case RRLP_Component_PR_posCapabilityRsp:
            break;
	default:
	    croak("Invalid value for component type %d, expecting between %d .. %d",
		    (int)kind_of,
		    (int)RRLP_Component_PR_msrPositionReq,
		    (int)RRLP_Component_PR_posCapabilityRsp);

	    break;
        }

        $self->component.present = kind_of;

        return;
    }
};

