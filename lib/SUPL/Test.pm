package SUPL::Test;

use strict;
use warnings;

use 5.010;

use Carp qw/croak/;

use SUPL::XS;

use Log::Any qw($log);
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

=head2 handle_supl_pdu

Starts a new flow of network initiated SUPL.

=cut

sub handle_supl_pdu
{
    my ( $self, $enc_pdu ) = @_;

    _STRING($enc_pdu) or croak "Invalid argument for \$enc_pdu";

    my $supl_pdu = SUPL::XS::decode_ulp_pdu($enc_pdu);

    $log->is_debug()
      and
      $log->debugf( "received pdu containing message type %d", $supl_pdu->{message}->{present} );
    $log->is_trace() and $log->tracef( "pdu: %s", $supl_pdu->dump() );

    # decode_ulp_pdu croaks on error ...
    given ( $supl_pdu->{message}->{present} )
    {
        when (SUPL::XS::UlpMessage_PR_msSUPLINIT)
        {
            # ...
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
}

=head2 get_read_trigger

Called by L<SUPL::MainLoop> to add the managed socket to the list of file
handles monitored for havind data to receive.

=cut

sub get_read_trigger
{
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

    perldoc SUPL::Test

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
