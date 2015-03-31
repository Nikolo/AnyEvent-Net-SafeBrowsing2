package AnyEvent::Net::SafeBrowsing2::Utils;

use utf8;
use strict;

=head1 NAME

AnyEvent::Net::SafeBrowsing2::Utils - Utils function for SafeBrowsing2 module

=head1 FUNCTIONS

=head2 expand_range()

Explode list of ranges (1-3, 5, 7-11) into a list of numbers (1,2,3,5,7,8,9,10,11).

=cut

sub expand_range {
	my ($self, $range) = @_;
	die "Bad range ".$range if $range !~ /^[\d\-\,\s]+$/;
	$range =~ s/-/../g;
	$range =~ s/\s+//g;
	my %list = map {$_ => 1} eval $range;
	return [keys %list];
}

=head2 validate_data_mac()

Validate data against the MAC keys.

=cut

sub validate_data_mac {
	my ($self, %args) = @_;
	my $data          = $args{data}   || '';
	my $key           = $args{key}    || '';
	my $digest        = $args{digest} || '';
	my $logger        = $args{logger};
	my $hash = urlsafe_b64encode(hmac_sha1($data, $key));
	$hash .= '=';

	$logger->debug1("$hash / $digest\n") if $logger;

	return ($hash eq $digest);
}

=head2 trim()

Trim text

=cut

sub trim {
    my ($pkg, $text) = @_;
	$text =~ s/\A\s+//; 
	$text =~ s/\s+\z//;
	return $text;
}

1;
