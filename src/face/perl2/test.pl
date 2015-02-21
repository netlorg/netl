BEGIN { $| = 1; print "1..6\n"; }
END {print "not ok 1\n" unless $loaded;}
use Netl;
$loaded = 1;
print "ok 1\n";

################################################################################
# $Netl::Guts::yy_line_number;

use Netl::Guts;

if($Netl::Guts::yy_line_number == 1) {
	print "ok 2\n";
} else {
	print "not ok 2\n";
}

################################################################################
# Netl::Config

use Netl::Config;

Netl::Config::pre();
print "ok 3\n";
Netl::Config::parseline("log icmp name=ping type=echo");
print "ok 4\n";
Netl::Config::readfile("../../conf/netl.conf");
print "ok 5\n";
Netl::Config::post();
print "ok 6\n";
