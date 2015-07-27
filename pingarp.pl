#!/usr/bin/perl -w

# pingarp.pl
# pod at tail

use strict;
use Net::Ping;

my $subnet = shift;                  # a.b.c.d/nn subnet/bitwise_netma
+sk
my %file = (
nmapout   => 'panout',
nmapclean => 'pamclean',
pingout   => 'papout',
arpout    => 'paaout',
arpclean  => 'paaclean',
);
my %bin = (
nmap => '/usr/bin/nmap',         # Debian 2.2r3 "Espy"
arp  => '/usr/sbin/arp',         # Debian 2.2r3 "Espy"
);
my @nmapregex  = (                   # text to remove from nmap output
'^.*Log of.*$',                  # header line
'^.*\.0\).*$',                   # subnet lines
'^.*\.255\).*$',                 # broadcast lines
'^Host\s+.*\(',                  # text prior to IP address
'\) appears to be up\.',         # text following IP address
'^\s+',                          # whitespace-only lines
);
my @arpregex = (                     # text to remove from copied ARP
+table
'^.*\(incomplete\).*$',          # incomplete MAC address
'^Address\s+.*$',                # header line
'\sether\s',                     # HW type
'\s+C\s+eth0',                   # Flags, Mask, Iface
'^\s+',                          # whitespace-only lines
);




# Make sure that *something* was entered by user for subnet/netmask
unless ($subnet) {
print "\nUsage: pingarp a.b.c.d/nn<enter>\n",
    "where a.b.c.d is your local subnet ",
    "and nn is your bitwise netmask netmask.\n\n";
exit;
}
$bin{nmapsyntax} = "-sP $subnet -o $file{nmapout}",  # nmap v2.2


# Then check for valid subnet/mask from user to nmap
# ? how to prevent leading zeroes ? (nmap bombs on 'em)
# \. = octet boundry
# \/ = subnet-netmask separator
#    1st octet -  match 1-254
# [1-9]|(?:[1-9]|1\d|2[0-4])\d|25[0-4]
#    2nd, 3rd, 4th octets - match 0-254
# \d|(?:[1-9]|1\d|2[0-4])\d|25[0-4]
#    bitwise netmasks - 8..14, 16..22, 24..30
# [89]|1[012346789]|2[012456789]|30



print "\nChecking requirements.\n";
# if you got this far, Net::Ping must be installed,
# otherwise would have halted with compilation errors.
unless (-x $bin{nmap}) {
print "nmap not accessible where script expects.\n\n";
exit;
}
unless (-x $bin{arp}) {
print "arp not accessible where script expects.\n\n";
exit;
}



# Oddly enough, using nmap like this doesn't
# seem to properly populate system ARP table.
# System call uses "and" instead of "or" for some reason.
print "Building list of live hosts on local subnet.\n";
system ("$bin{nmap} $bin{nmapsyntax} > /dev/null") and (die "Error cal
+ling $bin{nmap}: $!");
open (NMAPOUT, "<$file{nmapout}")
or die "Error opening $file{nmapout} RO: $!";
open (NMAPCLEAN, ">$file{nmapclean}")
or die "Error opening $file{nmapclean} WO: $!";
while (<NMAPOUT>) {
foreach my $regex(@nmapregex) {s/$regex//g;}
print NMAPCLEAN $_;
}
close (NMAPOUT)
or die "Error closing $file{nmapout}: $!";
close (NMAPCLEAN)
or die "Error closing $file{nmapclean}: $!";


# So we have to do this with real pings.
print "Populating local ARP table.\n";
open (NMAPCLEAN, "<$file{nmapclean}")
or die "Error opening $file{nmapclean} RO: $!";
open (PINGOUT, ">$file{pingout}")
or die "Error opening $file{pingout} WO: $!";
my @hosts = (<NMAPCLEAN>);
my $p = Net::Ping->new("icmp");
foreach my $host (@hosts) {
print PINGOUT "$host is ";
print PINGOUT 'NOT ' unless $p->ping($host, 2);
print PINGOUT "reachable.\n";
sleep (1);
}
$p->close();
# don't actually do anything with $file{pingout}, save it anyway.
close (NMAPCLEAN)
or die "Error closing $file{nmapclean}: $!";
close (PINGOUT)
or die "Error closing $file{pingout}: $!";


print "Querying ARP table and cleaning results.\n";
system("$bin{arp} > $file{arpout}")
and die "Error running $bin{arp}: $!";
open (ARPOUT, "<$file{arpout}")
or die "Error opening $file{arpout} RO: $!";
open (ARPCLEAN, ">$file{arpclean}")
or die "Error opening $file{arpclean} WO: $!";
while (<ARPOUT>) {
foreach my $regex(@arpregex) {s/$regex//g;}
tr/A-Z/a-z/;
print ARPCLEAN $_;
}
close (ARPOUT)
or die "Error closing $file{arpout}: $!";
close (ARPCLEAN)
or die "Error closing $file{arpclean}: $!";



print(
"\nOutput files:\n",
"  finished results:      $file{arpclean}\n",
"  raw arp table:         $file{arpout}\n",
"  ping-responding hosts: $file{pingout}\n",
"  nmap-responding hosts: $file{nmapclean}\n",
"  raw nmap results:      $file{nmapout}\n\n"
);
