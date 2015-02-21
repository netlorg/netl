use English;
use Config;
use ExtUtils::MakeMaker;

if($ARGV[0] eq '--config') {
	shift;
	$libdir = shift;
	$incdir = shift;
} else {

	$libdir = find('libnetl.so', 'netl library',
			'/usr/local/lib/netl',
			'/usr/local/lib',
			'/usr/lib/netl',
			'/lib/netl');
	$incdir = find('netl/netl.h', 'netl include',
			"$libdir/include",
			'/usr/local/lib/netl/include',
			'/usr/lib/netl/include',
			'/usr/local/include',
			'/usr/include');
}

print "configuring for \n\$libdir = $libdir\n\$incdir = $incdir\n";

open(FP, ">Netl/Dirs.pm") || die "unable to write to Netl/Dirs.pm $!";
print FP "

package Netl::Dirs;

\$startperl = \"$Config{'startperl'}\";
\$libdir = \"$libdir\";
\$incdir = \"$incdir\";

1;
";
close FP;

WriteMakefile(
	'DISTNAME'	=> 'tknetl',

	'NAME'		=> 'Netl',

	'VERSION_FROM'	=> 'Netl.pm',

	'LIBS'		=> ["-L$libdir -lnetl -ldl -lfl "], 

	'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 

	'INC'		=> "-I $incdir ",

	'EXE_FILES'	=> ['tknetl', 'tkneta' ],

	'clean'		=> {'FILES' => 'Netl/Dirs.pm'},
);

sub find {
	my $file = shift;
	my $name = shift;
	for(@_) {
		my $fred = $_;
		if(-e "$fred/$file") {
			my $answer = $fred;
			if(-l $answer) {
				$answer =~ m!^(.*)/!;
				my $base = $1;
				$answer = "$base/" . readlink($answer);
			}
			return $answer;
		}
	}
	print "could not find $name directory.  enter location:\n";
	print "> ";
	my $dir = <STDIN>;
	chomp($dir);
	return $dir ;
}         

