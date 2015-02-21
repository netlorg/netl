#!/usr/bin/perl

require 'find.pl';

find('.');
exit;

%dir = ();

sub wanted {
	my $dir, $filename, $count;
	if(/^.*\.c$/) {
		#print "WARN:$name\n";
		return if $name =~ /^\.\/perl\//;
		return if $name =~ /^\.\/old\//;
		return if $name =~ /^\.\/other\//;
		return if $name =~ /^\.\/build\//;
		($filename = $name) =~ s!^\./!!;
		$filename =~ m!^(.*/)!;
		$dir = $1;
		unless(defined $dir{$dir}) {
			$dir{$dir} = 1;
			print "${dir}Makefile.dep\n";
			unlink "Makefile.dep";
		}
		$filename =~ s!^(.*)/!!g;
		$count = count($dir);
		#print "$dir$filename:$count\n";
		open(FP, $filename) || die "unable to open $filename for read $!";
		open(DEPEND, '>>Makefile.dep') || die "unable to open ${dir}.dep for append $!";
		($obj = $filename) =~ s/\.c$/\.o/;
		$obj = 'die_trickle.o die_blank.o' if $obj eq 'die.o';
		print DEPEND "$obj: ";
		while(<FP>) {
			if(/^\s*#include\s+\"(.*?)"/) {
				$header_file = ('$(ONELEVEL)' x $count) . "include/$1";
				$header_file = $1 if -e $1;
				#print "\$header_file = \"$header_file\"\n";
				if($header_file =~ 
				   /(version\.h|guess\.h)$/) {
					print DEPEND "\\\n\t\$(BUILD_DIRx)include/netl/$1 ";
				} elsif($header_file eq 'filt.h') {
					print DEPEND "\\\n\t\$(SOURCE_DIRx)\$(ONELEVEL)filt/filt.h ";
				} else {
					print DEPEND "\\\n\t\$(SOURCE_DIRx)$header_file "
						unless /\.tab\.h/ || /simdl/;
				}
			}
		}
		print DEPEND "\n";
	}
}

sub count {
	$_ = shift;
	my $count = 0;
	while(s!/!!) { $count++ }
	return $count;
}
