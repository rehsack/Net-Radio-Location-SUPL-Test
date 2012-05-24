package SUPL::DBusObject::Translator;

use strict;
use warnings;

use 5.014;

our $VERSION = 0.001;

use ULP_PDU;

use base qw(SUPL::DBusObject);
use Net::DBus::Exporter qw(org.ofono.supl.Translator);

sub new
{
    my ($class, %cfg) = @_;
    my $self = $class->SUPER::new(%cfg);

    bless( $self, $class );

    SUPL::MainLoop->add($self);

    return $self;
}

dbus_method("SuplPduStringToXmlString", ["string"], ["string"]);
sub SuplPduStringToXmlString
{
    my ($self, $enc_pdu) = @_;
    my $supl_xml = ULP_PDU::ulp_pdu_to_xml($enc_pdu);
    return $supl_xml;
}

dbus_method("SuplPduArrayToXmlString", [["array", "byte"]], ["string"]);
sub SuplPduArrayToXmlString
{
    my ($self, $pdu) = @_;
    my $pdu_str = join( "", map { chr($_) } @$pdu );
    return $self->SuplPduStringToXmlString($pdu_str);
}

dbus_method("SuplPduHexStringToXmlString", ["string"], ["string"]);
sub SuplPduHexStringToXmlString
{
    my ($self, $pdu) = @_;
    my $pdu_str = pack( "H*", $pdu );
    return $self->SuplPduStringToXmlString($pdu_str);
}
