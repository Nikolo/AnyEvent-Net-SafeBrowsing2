package AnyEvent::Net::SafeBrowsing2::Log;

use utf8;
use strict;
use Mouse;
use Data::Dumper;

has debug_level => (is => 'ro', isa => 'Str', default => 'info');
#has levels => (is => 'rw', isa => 'HashRef');
my $iter = 0;
my $levels = {};
for (qw/stat fatal error warn info debug1 debug2 debug3/){
	my $i = $iter;
	my $name = $_;
	__PACKAGE__->meta->add_method("log_".$_ => sub {
			my $self = shift; 
			return if $i > $self->levels->{$self->debug_level}; 
			my @call = caller();
			my $mess = join " ", map {ref $_ ? Dumper($_) : $_} @_;
			warn "LL_".$name.": ".$mess." at ".$call[0]." line ".$call[2];
		});
	$levels->{$_} = $iter;
	$iter++;
}
__PACKAGE__->meta->add_attribute(levels => {is => 'rw', isa => 'HashRef'});

sub BUILD {
	my $self = shift;
	$self->levels($levels);
	return $self;
}

no Mouse;
__PACKAGE__->meta->make_immutable();

1;
