/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * Copyright (c) 2003-2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * asleap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * MS-CHAPv2 and attack tools by Jochen Eisinger, Univ. of Freiburg
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "../common.h"


/* This program reads through the index file and prints out the corresponding
   password string entry from the associated dict+hash list.  Written for
   testing the indexing code, but could be used for validating an index file,
   
   This code only examines the first entry in the dict+hash file, so the verbose
   output will display one hash and password per key entry.  It's not really
   useful for anything more than validating my indexing code. */

int main(int argc, char *argv[]) {

    struct hashpass_rec rec;
    struct hashpassidx_rec idxrec;
    int    hashfile;
    FILE   *idxfile;
    int    readlen, passwordlen, j, verbose=1, badmatches=0;
    unsigned long    idxfilelen=0, idxreadlentot=0;
    char   password[33];
    unsigned char hash[16];
    struct stat hashfilestat, idxfilestat;
    caddr_t base, ptr;

    if (argc < 3) {

        printf("testidx: Test the index file against a genkeys hash file.\n");
        printf("  usage: %s hashfile indexfile\n", argv[0]);
        exit(1);
    }

    printf("Testing integrity of index (%s) and hash file (%s).\n",
        argv[2], argv[1]);
    printf("This could take some time ...\n");
    fflush(stdout);


    /* We use buffered I/O to improve efficiency in reading the index file,
       and use an unbuffered file handle for the hash file.  Since we are only
       referencing the hash file as it exists with mmap(), we don't need to use
       buffered I/O. */

    if((hashfile = open(argv[1], O_RDONLY, 0)) < 0) {
        perror("open");
        exit(1);
    }

    if ((idxfile = fopen(argv[2], "r")) == NULL) {
        perror("fopen");
        close(hashfile);
        exit(1);
    }

    /* Determine the file size to pass to mmap.  Should error-check this. */
    stat(argv[1], &hashfilestat);

    /* Determine the file size so we know when to stop reading. */
    stat(argv[2], &idxfilestat);
    idxfilelen = idxfilestat.st_size;

    /* mmap the file into memory */
    base = mmap(0, hashfilestat.st_size, PROT_READ, MAP_SHARED, hashfile, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        close(hashfile);
        close(idxfile);
        exit(1);
    }

    /* fd for hash file is no longer needed */
    close(hashfile);


    /* Read through the index file */
    while (fread(&idxrec, sizeof(idxrec), 1, idxfile) == 1) {

        memset(&rec, 0, sizeof(rec));
        memset(&password, 0, sizeof(password));
        memset(&hash, 0, sizeof(hash));

        /* Use the offset from the index file to populate this record */
        memcpy(&rec.rec_size, base+idxrec.offset, sizeof(rec.rec_size));
        passwordlen = rec.rec_size - 17;

        /* With the record size, copy the password into the record */
        memcpy(password, base+idxrec.offset+1, passwordlen);

        /* Populate the hash as well */
        memcpy(&hash, base+idxrec.offset+1+passwordlen, sizeof(hash));

        /* Compare the last two bytes of the hash stored as the key in the
           index file with the last two bytes of the hash in the hash+dict
           file.  If the don't match, we've got a problem. */
        if ((memcmp(&idxrec.hashkey[0], &hash[14], 1) != 0) ||
            memcmp(&idxrec.hashkey[1], &hash[15], 1) != 0) {
            fprintf(stderr, "Hashes do not match: %02x%02x\t%02x%02x\t%s\n",
                idxrec.hashkey[0], idxrec.hashkey[1], hash[14], hash[15],
                password);
            badmatches++;
        }

        if (verbose) {
            printf("Offset: %ld\thash: %02x%02x\tpassword: %s\t\thash: ", 
                idxrec.offset, idxrec.hashkey[0], idxrec.hashkey[1], password);
            for (j=0; j < sizeof(hash); j++) printf("%02x", hash[j]);
            printf("\n");
        }

        /* Add record size to total number of bytes read.  If we are at the
           end of the file, break */
        idxreadlentot += sizeof(idxrec);
        if (idxreadlentot == idxfilelen) {
            break;
        }

    }

    munmap(base, hashfilestat.st_size);
    fclose(idxfile);

    printf("Errors detected: %d\n", badmatches);

    exit(0);
}
