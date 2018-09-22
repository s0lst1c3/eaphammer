# This script will strip all the non-printable ASCII characters in a given
# input.
# e.x. ./strip-nonascii.pl < big-dict >big-dict-clean
#!/usr/bin/perl

while(<STDIN>) {
    s/[\x00-\x1f\x7f-\xff]//g;
    print "$_\n";
}
