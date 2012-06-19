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

%include "asn1/RRLP-PDU.h"
%include "asn1/RRLP-Component.h"
%include "asn1/MsrPosition-Req.h"
%include "asn1/MsrPosition-Rsp.h"
%include "asn1/PositionInstruct.h"
%include "asn1/MethodType.h"
typedef long Accuracy_t;


