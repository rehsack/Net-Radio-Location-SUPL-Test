# This file was automatically generated by SWIG (http://www.swig.org).
# Version 2.0.6
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.

package Net::Radio::Location::SUPL::XS;
use base qw(Exporter);
use base qw(DynaLoader);
package Net::Radio::Location::SUPL::XSc;
bootstrap Net::Radio::Location::SUPL::XS;
package Net::Radio::Location::SUPL::XS;
@EXPORT = qw();

# ---------- BASE METHODS -------------

package Net::Radio::Location::SUPL::XS;

sub TIEHASH {
    my ($classname,$obj) = @_;
    return bless $obj, $classname;
}

sub CLEAR { }

sub FIRSTKEY { }

sub NEXTKEY { }

sub FETCH {
    my ($self,$field) = @_;
    my $member_func = "swig_${field}_get";
    $self->$member_func();
}

sub STORE {
    my ($self,$field,$newval) = @_;
    my $member_func = "swig_${field}_set";
    $self->$member_func($newval);
}

sub this {
    my $ptr = shift;
    return tied(%$ptr);
}


# ------- FUNCTION WRAPPERS --------

package Net::Radio::Location::SUPL::XS;

*encode_ulp_pdu = *Net::Radio::Location::SUPL::XSc::encode_ulp_pdu;
*decode_ulp_pdu = *Net::Radio::Location::SUPL::XSc::decode_ulp_pdu;
*ulp_pdu_to_xml = *Net::Radio::Location::SUPL::XSc::ulp_pdu_to_xml;
*dump_ulp_pdu = *Net::Radio::Location::SUPL::XSc::dump_ulp_pdu;

############# Class : Net::Radio::Location::SUPL::XS::SUPLAUTHREQ_t ##############

package Net::Radio::Location::SUPL::XS::SUPLAUTHREQ_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_sETNonce_get = *Net::Radio::Location::SUPL::XSc::SUPLAUTHREQ_t_sETNonce_get;
*swig_sETNonce_set = *Net::Radio::Location::SUPL::XSc::SUPLAUTHREQ_t_sETNonce_set;
*swig_keyIdentity2_get = *Net::Radio::Location::SUPL::XSc::SUPLAUTHREQ_t_keyIdentity2_get;
*swig_keyIdentity2_set = *Net::Radio::Location::SUPL::XSc::SUPLAUTHREQ_t_keyIdentity2_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLAUTHREQ_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLAUTHREQ_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLAUTHREQ_t($self);
        delete $OWNER{$self};
    }
}

sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLAUTHREQ_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SUPLAUTHRESP_t ##############

package Net::Radio::Location::SUPL::XS::SUPLAUTHRESP_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_sPCAuthKey_get = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t_sPCAuthKey_get;
*swig_sPCAuthKey_set = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t_sPCAuthKey_set;
*swig_keyIdentity3_get = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t_keyIdentity3_get;
*swig_keyIdentity3_set = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t_keyIdentity3_set;
*swig_statusCode_get = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t_statusCode_get;
*swig_statusCode_set = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t_statusCode_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLAUTHRESP_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLAUTHRESP_t($self);
        delete $OWNER{$self};
    }
}

sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLAUTHRESP_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SUPLEND_t ##############

package Net::Radio::Location::SUPL::XS::SUPLEND_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_position_get = *Net::Radio::Location::SUPL::XSc::SUPLEND_t_position_get;
*swig_position_set = *Net::Radio::Location::SUPL::XSc::SUPLEND_t_position_set;
*swig_statusCode_get = *Net::Radio::Location::SUPL::XSc::SUPLEND_t_statusCode_get;
*swig_statusCode_set = *Net::Radio::Location::SUPL::XSc::SUPLEND_t_statusCode_set;
*swig_ver_get = *Net::Radio::Location::SUPL::XSc::SUPLEND_t_ver_get;
*swig_ver_set = *Net::Radio::Location::SUPL::XSc::SUPLEND_t_ver_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLEND_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLEND_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLEND_t($self);
        delete $OWNER{$self};
    }
}

sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLEND_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SUPLINIT_t ##############

package Net::Radio::Location::SUPL::XS::SUPLINIT_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_posMethod_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_posMethod_get;
*swig_posMethod_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_posMethod_set;
*swig_notification_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_notification_get;
*swig_notification_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_notification_set;
*swig_sLPAddress_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_sLPAddress_get;
*swig_sLPAddress_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_sLPAddress_set;
*swig_qoP_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_qoP_get;
*swig_qoP_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_qoP_set;
*swig_sLPMode_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_sLPMode_get;
*swig_sLPMode_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_sLPMode_set;
*swig_mAC_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_mAC_get;
*swig_mAC_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_mAC_set;
*swig_keyIdentity_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_keyIdentity_get;
*swig_keyIdentity_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t_keyIdentity_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLINIT_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLINIT_t($self);
        delete $OWNER{$self};
    }
}

sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLINIT_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SUPLPOS_t ##############

package Net::Radio::Location::SUPL::XS::SUPLPOS_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_posPayLoad_get = *Net::Radio::Location::SUPL::XSc::SUPLPOS_t_posPayLoad_get;
*swig_posPayLoad_set = *Net::Radio::Location::SUPL::XSc::SUPLPOS_t_posPayLoad_set;
*swig_velocity_get = *Net::Radio::Location::SUPL::XSc::SUPLPOS_t_velocity_get;
*swig_velocity_set = *Net::Radio::Location::SUPL::XSc::SUPLPOS_t_velocity_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLPOS_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLPOS_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLPOS_t($self);
        delete $OWNER{$self};
    }
}

sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLPOS_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SUPLPOSINIT_t ##############

package Net::Radio::Location::SUPL::XS::SUPLPOSINIT_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_sETCapabilities_get = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_sETCapabilities_get;
*swig_sETCapabilities_set = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_sETCapabilities_set;
*swig_requestedAssistData_get = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_requestedAssistData_get;
*swig_requestedAssistData_set = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_requestedAssistData_set;
*swig_locationId_get = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_locationId_get;
*swig_locationId_set = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_locationId_set;
*swig_position_get = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_position_get;
*swig_position_set = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_position_set;
*swig_sUPLPOS_get = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_sUPLPOS_get;
*swig_sUPLPOS_set = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_sUPLPOS_set;
*swig_ver_get = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_ver_get;
*swig_ver_set = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_ver_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLPOSINIT_t($self);
        delete $OWNER{$self};
    }
}

*set_capabilities = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_set_capabilities;
*set_requested_assist_data = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_set_requested_assist_data;
*update_requested_assist_data = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_update_requested_assist_data;
*set_requested_assist_navigation_modell = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_set_requested_assist_navigation_modell;
*set_gsm_location_info = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_set_gsm_location_info;
*set_position_estimate = *Net::Radio::Location::SUPL::XSc::SUPLPOSINIT_t_set_position_estimate;
sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLPOSINIT_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SUPLRESPONSE_t ##############

package Net::Radio::Location::SUPL::XS::SUPLRESPONSE_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_posMethod_get = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_posMethod_get;
*swig_posMethod_set = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_posMethod_set;
*swig_sLPAddress_get = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_sLPAddress_get;
*swig_sLPAddress_set = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_sLPAddress_set;
*swig_sETAuthKey_get = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_sETAuthKey_get;
*swig_sETAuthKey_set = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_sETAuthKey_set;
*swig_keyIdentity4_get = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_keyIdentity4_get;
*swig_keyIdentity4_set = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t_keyIdentity4_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLRESPONSE_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLRESPONSE_t($self);
        delete $OWNER{$self};
    }
}

sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLRESPONSE_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SUPLSTART_t ##############

package Net::Radio::Location::SUPL::XS::SUPLSTART_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_sETCapabilities_get = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t_sETCapabilities_get;
*swig_sETCapabilities_set = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t_sETCapabilities_set;
*swig_locationId_get = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t_locationId_get;
*swig_locationId_set = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t_locationId_set;
*swig_qoP_get = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t_qoP_get;
*swig_qoP_set = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t_qoP_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SUPLSTART_t__asn_ctx_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SUPLSTART_t($self);
        delete $OWNER{$self};
    }
}

sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SUPLSTART_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::ULP_PDU_t ##############

package Net::Radio::Location::SUPL::XS::ULP_PDU_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_length_get = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_length_get;
*swig_length_set = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_length_set;
*swig_version_get = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_version_get;
*swig_version_set = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_version_set;
*swig_sessionID_get = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_sessionID_get;
*swig_sessionID_set = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_sessionID_set;
*swig_message_get = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_message_get;
*swig_message_set = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_message_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t__asn_ctx_set;
sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_ULP_PDU_t(@_);
    bless $self, $pkg if defined($self);
}

sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_ULP_PDU_t($self);
        delete $OWNER{$self};
    }
}

*set_version = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_set_version;
*setSetSessionId_to_imsi = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_setSetSessionId_to_imsi;
*setSetSessionId_to_msisdn = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_setSetSessionId_to_msisdn;
*copy_SlpSessionId = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_copy_SlpSessionId;
*set_message_type = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_set_message_type;
*encode = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_encode;
*dump = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_dump;
*xml_dump = *Net::Radio::Location::SUPL::XSc::ULP_PDU_t_xml_dump;
sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::UlpMessage_t ##############

package Net::Radio::Location::SUPL::XS::UlpMessage_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_present_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_present_get;
*swig_present_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_present_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t__asn_ctx_set;
*swig_choice_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_get;
*swig_choice_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_set;
sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_UlpMessage_t(@_);
    bless $self, $pkg if defined($self);
}

sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_UlpMessage_t($self);
        delete $OWNER{$self};
    }
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::UlpMessage_t_choice ##############

package Net::Radio::Location::SUPL::XS::UlpMessage_t_choice;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_msSUPLINIT_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLINIT_get;
*swig_msSUPLINIT_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLINIT_set;
*swig_msSUPLSTART_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLSTART_get;
*swig_msSUPLSTART_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLSTART_set;
*swig_msSUPLRESPONSE_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLRESPONSE_get;
*swig_msSUPLRESPONSE_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLRESPONSE_set;
*swig_msSUPLPOSINIT_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLPOSINIT_get;
*swig_msSUPLPOSINIT_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLPOSINIT_set;
*swig_msSUPLPOS_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLPOS_get;
*swig_msSUPLPOS_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLPOS_set;
*swig_msSUPLEND_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLEND_get;
*swig_msSUPLEND_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLEND_set;
*swig_msSUPLAUTHREQ_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLAUTHREQ_get;
*swig_msSUPLAUTHREQ_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLAUTHREQ_set;
*swig_msSUPLAUTHRESP_get = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLAUTHRESP_get;
*swig_msSUPLAUTHRESP_set = *Net::Radio::Location::SUPL::XSc::UlpMessage_t_choice_msSUPLAUTHRESP_set;
sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_UlpMessage_t_choice(@_);
    bless $self, $pkg if defined($self);
}

sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_UlpMessage_t_choice($self);
        delete $OWNER{$self};
    }
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SLPAddress_t ##############

package Net::Radio::Location::SUPL::XS::SLPAddress_t;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_present_get = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_present_get;
*swig_present_set = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_present_set;
*swig__asn_ctx_get = *Net::Radio::Location::SUPL::XSc::SLPAddress_t__asn_ctx_get;
*swig__asn_ctx_set = *Net::Radio::Location::SUPL::XSc::SLPAddress_t__asn_ctx_set;
*swig_choice_get = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_choice_get;
*swig_choice_set = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_choice_set;
sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SLPAddress_t($self);
        delete $OWNER{$self};
    }
}

*set_ipaddress = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_set_ipaddress;
*set_fqdn = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_set_fqdn;
*is_ipv4 = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_is_ipv4;
*is_ipv6 = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_is_ipv6;
*is_ip = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_is_ip;
*is_fqdn = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_is_fqdn;
*is_valid = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_is_valid;
sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SLPAddress_t(@_);
    bless $self, $pkg if defined($self);
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


############# Class : Net::Radio::Location::SUPL::XS::SLPAddress_t_choice ##############

package Net::Radio::Location::SUPL::XS::SLPAddress_t_choice;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( Net::Radio::Location::SUPL::XS );
%OWNER = ();
%ITERATORS = ();
*swig_iPAddress_get = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_choice_iPAddress_get;
*swig_iPAddress_set = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_choice_iPAddress_set;
*swig_fQDN_get = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_choice_fQDN_get;
*swig_fQDN_set = *Net::Radio::Location::SUPL::XSc::SLPAddress_t_choice_fQDN_set;
sub new {
    my $pkg = shift;
    my $self = Net::Radio::Location::SUPL::XSc::new_SLPAddress_t_choice(@_);
    bless $self, $pkg if defined($self);
}

sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        Net::Radio::Location::SUPL::XSc::delete_SLPAddress_t_choice($self);
        delete $OWNER{$self};
    }
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


# ------- CONSTANT STUBS -------

package Net::Radio::Location::SUPL::XS;

sub setcap_pos_tech_agpsSETassisted () { $Net::Radio::Location::SUPL::XSc::setcap_pos_tech_agpsSETassisted }
sub setcap_pos_tech_agpsSETBased () { $Net::Radio::Location::SUPL::XSc::setcap_pos_tech_agpsSETBased }
sub setcap_pos_tech_autonomousGPS () { $Net::Radio::Location::SUPL::XSc::setcap_pos_tech_autonomousGPS }
sub setcap_pos_tech_aFLT () { $Net::Radio::Location::SUPL::XSc::setcap_pos_tech_aFLT }
sub setcap_pos_tech_eCID () { $Net::Radio::Location::SUPL::XSc::setcap_pos_tech_eCID }
sub setcap_pos_tech_eOTD () { $Net::Radio::Location::SUPL::XSc::setcap_pos_tech_eOTD }
sub setcap_pos_tech_oTDOA () { $Net::Radio::Location::SUPL::XSc::setcap_pos_tech_oTDOA }
sub setcap_pos_proto_tia801 () { $Net::Radio::Location::SUPL::XSc::setcap_pos_proto_tia801 }
sub setcap_pos_proto_rrlp () { $Net::Radio::Location::SUPL::XSc::setcap_pos_proto_rrlp }
sub setcap_pos_proto_rrc () { $Net::Radio::Location::SUPL::XSc::setcap_pos_proto_rrc }
sub reqassistdata_almanacRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_almanacRequested }
sub reqassistdata_utcModelRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_utcModelRequested }
sub reqassistdata_ionosphericModelRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_ionosphericModelRequested }
sub reqassistdata_dgpsCorrectionsRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_dgpsCorrectionsRequested }
sub reqassistdata_referenceLocationRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_referenceLocationRequested }
sub reqassistdata_referenceTimeRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_referenceTimeRequested }
sub reqassistdata_acquisitionAssistanceRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_acquisitionAssistanceRequested }
sub reqassistdata_realTimeIntegrityRequested () { $Net::Radio::Location::SUPL::XSc::reqassistdata_realTimeIntegrityRequested }
sub UlpMessage_PR_NOTHING () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_NOTHING }
sub UlpMessage_PR_msSUPLINIT () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLINIT }
sub UlpMessage_PR_msSUPLSTART () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLSTART }
sub UlpMessage_PR_msSUPLRESPONSE () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLRESPONSE }
sub UlpMessage_PR_msSUPLPOSINIT () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLPOSINIT }
sub UlpMessage_PR_msSUPLPOS () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLPOS }
sub UlpMessage_PR_msSUPLEND () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLEND }
sub UlpMessage_PR_msSUPLAUTHREQ () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLAUTHREQ }
sub UlpMessage_PR_msSUPLAUTHRESP () { $Net::Radio::Location::SUPL::XSc::UlpMessage_PR_msSUPLAUTHRESP }
sub SLPAddress_PR_NOTHING () { $Net::Radio::Location::SUPL::XSc::SLPAddress_PR_NOTHING }
sub SLPAddress_PR_iPAddress () { $Net::Radio::Location::SUPL::XSc::SLPAddress_PR_iPAddress }
sub SLPAddress_PR_fQDN () { $Net::Radio::Location::SUPL::XSc::SLPAddress_PR_fQDN }
sub PrefMethod_agpsSETassistedPreferred () { $Net::Radio::Location::SUPL::XSc::PrefMethod_agpsSETassistedPreferred }
sub PrefMethod_agpsSETBasedPreferred () { $Net::Radio::Location::SUPL::XSc::PrefMethod_agpsSETBasedPreferred }
sub PrefMethod_noPreference () { $Net::Radio::Location::SUPL::XSc::PrefMethod_noPreference }
sub SLPMode_proxy () { $Net::Radio::Location::SUPL::XSc::SLPMode_proxy }
sub SLPMode_nonProxy () { $Net::Radio::Location::SUPL::XSc::SLPMode_nonProxy }
sub Status_stale () { $Net::Radio::Location::SUPL::XSc::Status_stale }
sub Status_current () { $Net::Radio::Location::SUPL::XSc::Status_current }
sub Status_unknown () { $Net::Radio::Location::SUPL::XSc::Status_unknown }

# ------- VARIABLE STUBS --------

package Net::Radio::Location::SUPL::XS;

*asn_DEF_SUPLAUTHREQ = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLAUTHREQ;
*asn_DEF_SUPLAUTHRESP = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLAUTHRESP;
*asn_DEF_SUPLEND = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLEND;
*asn_DEF_SUPLINIT = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLINIT;
*asn_DEF_SUPLPOS = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLPOS;
*asn_DEF_SUPLPOSINIT = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLPOSINIT;
*asn_DEF_SUPLRESPONSE = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLRESPONSE;
*asn_DEF_SUPLSTART = *Net::Radio::Location::SUPL::XSc::asn_DEF_SUPLSTART;
*asn_DEF_ULP_PDU = *Net::Radio::Location::SUPL::XSc::asn_DEF_ULP_PDU;
*asn_DEF_UlpMessage = *Net::Radio::Location::SUPL::XSc::asn_DEF_UlpMessage;
*asn_DEF_SLPAddress = *Net::Radio::Location::SUPL::XSc::asn_DEF_SLPAddress;
1;
