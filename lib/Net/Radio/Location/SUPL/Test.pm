package Net::Radio::Location::SUPL::Test;

use strict;
use warnings;

use 5.010;

use Carp qw/croak/;

use Net::Radio::Location::SUPL::XS;

use Log::Any qw($log);
use Digest::SHA;

use Socket (
    qw(
      AF_INET6 PF_INET6 SOCK_RAW SOCK_STREAM INADDR_ANY SOCK_DGRAM
      AF_INET SO_REUSEADDR SO_REUSEPORT AF_UNSPEC SO_BROADCAST
      sockaddr_in
      )
);

use Params::Util qw(_STRING);

use Net::Radio::Location::SUPL::MainLoop;

=head1 NAME

Net::Radio::Location::SUPL::Test - Run Test Use-Cases for SUPL

=head1 DESCRIPTION

This module implements state machine for handling SUPL packets.

=head1 METHODS

=cut

our $VERSION = '0.001';

=head2 new

instantiates new Net::Radio::Location::SUPL::Test state machine

=cut

sub new
{
    my ( $class, %cfg ) = @_;
    return bless( { config => \%cfg }, $class );
}

{    #protect global variables
    my $connection_id = 0;
    sub _get_next_session_id { return ++$connection_id; }

    my %connect_pkgs;
    my %domain_abbrevs = (
                           IPV4   => AF_INET,
                           IPV6   => AF_INET6,
                           UNSPEC => AF_UNSPEC,
                         );

    sub _init_connect_pkgs
    {
        eval {
            require IO::Socket::SSL;
            $connect_pkgs{"IO::Socket::SSL"} = 1;
        };
        eval {
            require IO::Socket::INET;
            $connect_pkgs{"IO::Socket::INET"} = 1;
        };
        eval {
            require IO::Socket::INET6;
            $connect_pkgs{"IO::Socket::INET6"} = 1;
        };
    }

    sub _can_ipv6
    {
        keys(%connect_pkgs) or _init_connect_pkgs();
        $connect_pkgs{"IO::Socket::INET6"};
    }
    sub _can_ssl { keys(%connect_pkgs) or _init_connect_pkgs(); $connect_pkgs{"IO::Socket::SSL"} }

    sub _connect
    {
        my ( $self, %params ) = @_;

        keys(%connect_pkgs) or _init_connect_pkgs();

        my ( $io_api, $addr, $port );
        my %connect_params;

        if ( defined( $self->{config}->{connect}->{ssl} ) )
        {
            if ( $self->{config}->{connect}->{ssl} && !_can_ssl() )
            {
                return $log->error("ssl configured but missing IO::Socket::SSL");
            }
            elsif ( $self->{config}->{connect}->{ssl} )
            {
                $io_api = "IO::Socket::SSL";
                # check whether SSL_hostname is a required parameter
            }
        }

        if ( defined( $self->{config}->{connect}->{target}->{domain} ) )
        {
            my $domain = uc( $self->{config}->{connect}->{target}->{domain} );
            if ( defined( $domain_abbrevs{$domain} ) )
            {
                $connect_params{Domain} = $domain_abbrevs{$domain};
            }
            else
            {
                $log->warningf(
                    "Invalid IP domain '%s' - allowed are 'IPv4', 'IPv6' and 'unspec'. Fall back to 'unspec'."
                );
            }
        }

        # IO::Socket::INET6( Domain => AF_INET, ... ) speaks IPv4
        $io_api //= _can_ipv6() ? "IO::Socket::INET6" : "IO::Socket::INET";

        $port = $params{port};
        $port //=
            $self->{config}->{connect}->{ssl}
          ? $self->{config}->{connect}->{target}->{supl_port} // 7275
          : $self->{config}->{connect}->{target}->{ulp_port}
          // 7276;    # find ULP spec telling default port for non-secure communication

        if ( defined( $params{host} ) )
        {
            $addr = $params{host};
        }
        elsif ( defined( $self->{config}->{connect}->{target}->{host} ) )
        {
            $addr = $self->{config}->{connect}->{target}->{host};
        }
        else
        {
            $addr = $self->_calc_hslp_from_imsi();    # XXX crash's - inimplemented!
        }

        $self->{connection} = $io_api->new(
                                            PeerAddr => $addr,
                                            PeerPort => $port,
                                            Proto    => "tcp",
                                            %connect_params
                                          )
          or return
          $log->errorf( "Can't connect to %s[:%d]: %s",
                        $io_api eq "IO::Socket::SSL" ? IO::Socket::SSL::errstr() : $@ );

        return $self->{connection};
    }
}

=head2 begin_ni_supl_seesion

Begins a network initiated SUPL session.

=cut

sub begin_ni_supl_seesion
{
    my ( $self, %params ) = @_;
    my ( $packet, $supl_pdu ) = @params{ "packet", "pdu" };

    # check proxy mode
    my ( $response_type, $response_addr );
    my $supl_init = $supl_pdu->{message}->{choice}->{msSUPLINIT};
    if ( $supl_init->{sLPMode} == Net::Radio::Location::SUPL::XS::SLPMode_proxy )
    {
        $log->debug("NI packet wants proxy mode");
        $response_type = Net::Radio::Location::SUPL::XS::UlpMessage_PR_msSUPLPOSINIT;
    }
    else
    {
        # XXX might require additional effort to send SUPLEND in nonProxy
        #     mode which might make rejection of nonProxy mode superfluous
        $log->warning("nonProxy mode not supported");
        $response_type = Net::Radio::Location::SUPL::XS::UlpMessage_PR_msSUPLEND;
    }

    # check reply address (fqdn, ip...)
    if ( $supl_init->{sLPAddress}->is_fqdn() )
    {
        $response_addr = $supl_init->{sLPAddress}->{choice}->{fQDN};
        # check whether config wants to override
    }
    else
    {
        if ( defined( $self->{config}->{connect}->{target}->{host} ) )
        {
            $response_addr = $self->{config}->{connect}->{target}->{host};
        }
        else
        {
            $response_addr = $self->_calculate_response_addr();
        }
    }

    # compute verification checksum
    my $chksum = Digest::SHA1::hmac_sha1( $packet, $response_addr );
    if ( length($chksum) != 8 )
    {
        $log->errorf(
            "Something went wrong computing verification checksum - expected length is 8, computed length is %d",
            length($chksum)
        );
    }

    # connect (Net::SSLeay, IO::Socket::SSL?)
    $self->_connect( host => $response_addr ) or return;

    # register at MainLoop (or better in handle_pdu?)
    Net::Radio::Location::SUPL::MainLoop->add($self);

    # built SUPLPOSINIT/AUTHREQ
    my $pdu = Net::Radio::Location::SUPL::XS::ULP_PDU_t->new();

    $pdu->copy_SlpSessionId($supl_pdu);
    $pdu->setSetSessionId_to_imsi( _get_next_session_id(), $self->{config}->{ident}->{imsi} );
    $pdu->set_message_type(Net::Radio::Location::SUPL::XS::UlpMessage_PR_msSUPLPOSINIT);

    my $posinit = $pdu->{message}->{choice}->{msSUPLPOSINIT};
    $posinit->set_capabilities( Net::Radio::Location::SUPL::XS::setcap_pos_tech_agpsSETBased, Net::Radio::Location::SUPL::XS::PrefMethod_agpsSETBasedPreferred,
                                Net::Radio::Location::SUPL::XS::setcap_pos_proto_rrlp );
    my %mobile_ident;
    @mobile_ident{"mcc", "mnc", "msin"} = _split_imsi($self->{config}->{ident}->{imsi}); # probably read from org.ofono.NetworkRegistration
    $posinit->set_gsm_location_info( # XXX from IMSI!!!
                                     262,      # mcc -- Mobile Country Code
                                     2,        # mnc -- Mobile Network Code
                                     144,      # lac -- Location Area Code
                                     26993,    # cellid
                                     1         # ta -- Terminal Adaptor
                                   );
    $posinit->{locationId}->{status} = Net::Radio::Location::SUPL::XS::Status_stale;
    $posinit->set_position( gmtime(&now), 1, 53, 28 );    # XXX

    # verification hash
    $posinit->{ver} = $chksum;

    $self->{suplposinit}->{pdu} = $pdu;

    # encode packet
    $self->{suplposinit}->{packet} = $self->{suplposinit}->{pdu}->encode();

    # send response
    $self->{connection}->write( $self->{suplposinit}->{packet} );

    return;
}

=head2 handle_supl_pdu

Starts a new flow of network initiated SUPL.

=cut

sub handle_supl_pdu
{
    my ( $self, $enc_pdu ) = @_;

    _STRING($enc_pdu) or croak "Invalid argument for \$enc_pdu";

    my $supl_pdu = Net::Radio::Location::SUPL::XS::decode_ulp_pdu($enc_pdu);

    $log->is_debug()
      and
      $log->debugf( "received pdu containing message type %d", $supl_pdu->{message}->{present} );
    $log->is_trace() and $log->tracef( "pdu: %s", $supl_pdu->dump() );

    # decode_ulp_pdu croaks on error ...
    given ( $supl_pdu->{message}->{present} )
    {
        when (Net::Radio::Location::SUPL::XS::UlpMessage_PR_msSUPLINIT)
        {
            $self->begin_ni_supl_seesion( packet => $enc_pdu,
                                          pdu    => $supl_pdu );
        }
        default
        {
            # ...
        }
    }
}

=head2 trigger_read

Is called from the main-loop when the managed socket has incoming data.

=cut

sub trigger_read
{
    my $self = shift;
}

=head2 get_read_trigger

Called by L<Net::Radio::Location::SUPL::MainLoop> to add the managed socket to the list of file
handles monitored for havind data to receive.

=cut

sub get_read_trigger
{
    my $self = shift;
    $self->{connection};
}

sub DESTROY
{
    my $self = shift;
    $self->{connection} and $self->{connection}->close();
}

=head1 AUTHOR

Jens Rehsack, C<< <rehsack at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-supl-test at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=SUPL-Test>.
I will be notified, and then you'll automatically be notified of progress
on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Radio::Location::SUPL::Test

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=SUPL-Test>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/SUPL-Test>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/SUPL-Test>

=item * Search CPAN

L<http://search.cpan.org/dist/SUPL-Test/>

=back

=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Jens Rehsack.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1;
