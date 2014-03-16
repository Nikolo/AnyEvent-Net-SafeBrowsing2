package AnyEvent::Net::SafeBrowsing2::Log;

use utf8;
use strict;
use Data::Dumper;
use base 'Exporter';

my $dlevel = 'info';
my $iter = 0;
my $levels = {};
my @FUNC_ALL = ();

sub import {
	my $pkg = shift;
	$dlevel = shift if $_[0];
	__PACKAGE__->export_to_level(1,@_);
}

for (qw/stat fatal error warn info debug1 debug2 debug3/){
	my $i = $iter;
	my $name = $_;
	no strict 'refs';
	*{__PACKAGE__."::log_".$_} = sub {
			return if $i > $levels->{$dlevel};
			my @call = caller();
			my $mess = join " ", map {ref $_ ? Dumper($_) : $_} @_;
			warn "LL_".$name.": ".$mess." at ".$call[0]." line ".$call[2];
		};
	push @FUNC_ALL, "log_".$_;
	$levels->{$_} = $iter;
	$iter++;
}

our @EXPORT = @FUNC_ALL;
our @EXPORT_OK = @FUNC_ALL;
our %EXPORT_TAGS;
$EXPORT_TAGS{all} = \@EXPORT_OK;

1;
