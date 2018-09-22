#!/usr/bin/perl
# This script will read in dictionary words, one per line, and will print to
# stdout all permutations of the word with 00, 01, 02 .. 99 appended to the
# end of the word.  This will (obviously) grow your dictionary file by 100x,
# which may or may not be what you want. :)

if (@ARGV < 1) {
  die("Must supply a dictionary filename");
}

unless(open(DICTFILE, "$ARGV[0]")) {
  die("Error opening file: $!");
}

while ($word=<DICTFILE>) {
  printf("$word\n");
  chop($word); # Asumes \n after word - may or may not be true
  for($i=0; $i < 10; $i++) {
     for($j=0; $j < 10; $j++) {
         printf("%s%d%d\n", $word, $i, $j);
     }
  }
}

