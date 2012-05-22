package SUPL::MainLoop;

use strict;
use warnings;

our $VERSION = 0.001;

use Carp qw(croak);

use Net::DBus::Reactor;

my $instance;

sub new
{
    $instance and return $instance;

    my $class = $_[0];
    my $instance = bless( { objects => [] }, $class );

    return $instance;
}

sub add
{
    $instance or __PACKAGE__->new();

    $_[0]->isa(__PACKAGE__) and shift; # discard OO style 1st self argument
    scalar(@_) == 1 or croak "Insufficient arguments";

    my $obj = $_[0];

    if( $obj->can("trigger_read") )
    {
	my $fh = $obj->get_read_trigger();
	my $cb = sub {
	    $obj->trigger_read();
	};
	Net::DBus::Reactor->add_read( $fh, $cb, 1 ); # add callback on $fh is readable and enable
    }

    push( @{$instance->{objects}}, $obj );
}

sub remove
{
    $instance or croak "Uninitialized";

    $_[0]->isa(__PACKAGE__) and shift; # discard OO style 1st self argument
    scalar(@_) == 1 or croak "Insufficient arguments";

    my $obj = $_[0];
    my @managed = grep { $obj == $_ } @{$instance->{objects}};

    @managed or croak "Not managed";

    if( $obj->can("trigger_read") )
    {
	my $fh = $obj->get_read_trigger();
	Net::DBus::Reactor->remove_read( $fh ); # remove callback on $fh is readable
    }

    @{$instance->{objects}} = map { $_ == $obj ? () : ($_) } @{$instance->{objects}};

    scalar(@{$instance->{objects}}) == 0 and Net::DBus::Reactor->main()->shutdown();

    return;
}

sub run
{
    $instance or croak "Uninitialized";

    $_[0]->isa(__PACKAGE__) and shift; # discard OO style 1st self argument
    scalar(@{$instance->{objects}}) or croak "Nothing managed";

    Net::DBus::Reactor->main()->run();

    # XXX explicitely destroy managed objects or let __PACKAGE__::DESTROY handle it?

    return;
}

1;
