#!/usr/bin/perl -w

use Term::ANSIColor;

#imports
# ../../src/frontend/4s-import -v circular -f turtle -m http://example.org/ns/circular.ttl circular.ttl

#$kb_name = "query_test_".$ENV{'USER'};
$kb_name = "circular";

# names of tests that require LAQRS support
my @need_laqrs = ('count', 'union-nobind');

$dirname=`dirname '$0'`;
chomp $dirname;
chdir($dirname) || die "cannot cd to $dirname";
$outdir = "results";
$test = 1;
my @tests = ();
my $errs = 1;

$SIG{USR2} = 'IGNORE';

mkdir($outdir);

if (!@tests) {
	@tests = `ls queries`;
	chomp @tests;
}

if (`../../src/frontend/4s-query -h 2>&1 | grep LAQRS` eq '') {
	my %tmp;
	foreach $t (@tests) { $tmp{$t} ++; }
	foreach $t (@need_laqrs) { delete $tmp{$t}; }
	@tests = sort keys %tmp;
}

my $fails = 0;
my $passes = 0;
for $t (@tests) {
    chomp $t;
    if (index($t, "circular") < 0) {
        next;
    }
    if (!stat("exemplar/$t") && $test) {
        print("SKIP $t (no exemplar)\n");
        next;
    }
    unlink("$outdir/".$t);
    if ($errs) {
        $errout = "2>$outdir/$t-errs";
    } else {
        $errout = "";
    }
    print("[....] $t\r");
    my $ret = system("FORMAT=ascii LANG=C LC_ALL=C TESTPATH=../../src queries/$t $kb_name > $outdir/$t $errout");
    if ($ret == 2) {
        exit(2);
    }
    if ($test) {
        @diff = `diff exemplar/$t $outdir/$t 2>/dev/null`;
        if (@diff) {
            print("[");
            print color 'bold red';
            print("FAIL");
            print color 'reset';
            print("] $t\n");
            open(RES, ">> $outdir/$t-errs") || die 'cannot open error file';
            print RES "\n";
            print RES @diff;
            close(RES);
            $fails++;
        } else {
            print("[");
            print color 'bold green';
            print("PASS");
            print color 'reset';
            print("] $t\n");
            $passes++;
        }
    } else {
        print("[PROC] $t\n");
    }
}
print("Tests completed: passed $passes/".($fails+$passes)." ($fails fails)\n");
