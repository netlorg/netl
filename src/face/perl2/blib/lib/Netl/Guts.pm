package Netl::Guts::LineNumber;

use Netl;

sub TIESCALAR {
	my $class = shift;
	my $fred = 0;
	return bless \$fred, $class;
}

sub FETCH {
	my $value = Netl::Guts::_get_yy_line_number();
	return $value;
}

sub STORE {
	my($self, $value) = @_;
	Netl::Guts::_set_yy_line_number($value)
}

package Netl::Guts;

use Netl;

# _get_yy_line_number()
# _set_yy_line_number()

tie $yy_line_number, 'Netl::Guts::LineNumber';

1;
