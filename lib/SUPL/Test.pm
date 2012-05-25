package SUPL::Test;

use strict;
use warnings;

use 5.010;

use Carp qw/croak/;

use SUPL::XS;

use Digest::SHA;
use SUPL::MainLoop;

use Params::Util qw(_STRING);

=head1 NAME

SUPL::Test - Run Test Use-Cases for SUPL

=head1 DESCRIPTION

This module implements state machine for handling SUPL packets.

=head1 METHODS

=cut

our $VERSION = '0.001';

=head2 new

instantiates new SUPL::Test state machine

=cut

sub new
{
    my $class = shift;
    return bless( {}, $class );
}

=head2 setup

set parameters depending on state

=cut

sub setup
{
}

sub handle_supl_pdu
{
    my ($self, $enc_pdu) = @_;

    _STRING($enc_pdu) or croak "Invalid argument for \$enc_pdu";

    my $supl_pdu = SUPL::XS::decode_ulp_pdu($enc_pdu);

    # decode_ulp_pdu croaks on error ...
    given($supl_pdu->{message}->{present})
    {
	when(SUPL::XS::UlpMessage_PR_msSUPLINIT)
	{
	    # ...
	}
	default
	{
	    # ... 
	}
    }
}

sub trigger_read
{
}

sub get_read_trigger
{
}

1;
