/*
 * Copyright 2016 CSIRO
 *
 * This file is part of Mastik.
 *
 * Mastik is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mastik is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mastik.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>

#include <mastik/util.h>
#include <mastik/low.h>
#include <mastik/l3.h>

#define SAMPLES 200

// This structure is used to test different mapping strategies.
// Not relevant to the core logic of scanning.
struct descr {
  uint32_t flags;
  char *text;
};

// Different mapping strategies to test.
struct descr descr[] = {
  {0, 	"Default"},
  {L3FLAG_QUADRATICMAP, "Quadratic"},
  {L3FLAG_LINEARMAP, "Linear"},
  {L3FLAG_NOHUGEPAGES, "Small pages"},
  {L3FLAG_QUADRATICMAP|L3FLAG_NOHUGEPAGES, "Small pages, Quad."},
  {L3FLAG_LINEARMAP|L3FLAG_NOHUGEPAGES, "Small pages, Lin."},
  { 0, NULL}
};


int main(int ac, char **av) {
  // A brief delay to allow the system to stabilize.
  delayloop(3000000000U);

  // === SETUP PHASE ===
  // This section prepares the L3 cache environment for scanning.
  // It allocates a large memory buffer and uses a probing technique
  // to discover the underlying cache geometry.
  l3info_t l3i = (l3info_t)malloc(sizeof(struct l3info));
  l3i->associativity = 0;
  l3i->slices = 0;
  l3i->setsperslice = 0;
  l3i->bufsize = 0;
  l3i->flags = L3FLAG_QUADRATICMAP;
  l3i->progressNotification = NULL;
  l3i->progressNotificationData = NULL;

  // This loop tests various mapping strategies. For understanding the core
  // scanning logic, you can focus on a single iteration.
  for (int j = 0; j < 5; j++) {
    for (int i = 0; descr[i].text; i++) {
      uint64_t t = rdtscp64();
      l3i->associativity = 0;
      l3i->slices = 0;
      l3i->setsperslice = 0;
      l3i->bufsize = 0;
      l3i->flags = descr[i].flags;
      l3i->progressNotification = NULL;
      l3i->progressNotificationData = NULL;
      
      // The main call to prepare the L3 cache environment. This is where
      // the cache mapping and slice detection happens.
      l3pp_t l3 = l3_prepare(l3i, NULL);

      t = rdtscp64() - t;
      char l=' ';
      if (t > 2000) {
	t  = t / 1000;
	l = 'K';
      }
      if (t > 2000) {
	t  = t / 1000;
	l = 'M';
      }
      if (t > 2000) {
	t  = t / 1000;
	l = 'G';
      }
      if (t > 2000) {
	t  = t / 1000;
	l = 'T';
      }
      
      // === OUTPUT PHASE ===
      // This section prints the results of the cache scan.
      // It shows the time taken for the scan and the number of cache sets found.
      printf("// --- L3 Cache Scan Results --- //\n");
      printf("// Strategy: %s\n", descr[i].text);
      printf("// Time taken: %5lu%c cycles\n", t, l);
      printf("// Total cache sets found: %5d\n", l3_getSets(l3));
      printf("// This information is used to build a map of the L3 cache slices,\n");
      printf("// which is essential for targeted L3 side-channel attacks.\n");
      printf("// ------------------------------------ //\n");
      
      l3_release(l3);
    }
  }

  /*
  // This commented-out section shows how you would use the generated cache map
  // to perform a Prime+Probe attack on each set individually to see the timing differences.
  uint16_t *res = calloc(SAMPLES, sizeof(uint16_t));
  for (int i = 0; i < SAMPLES; i+= 4096/sizeof(uint16_t))
    res[i] = 1;
  
  for (int i = 0; i < nsets; i++) {
    l3_unmonitorall(l3);
    l3_monitor(l3, i);

    l3_repeatedprobecount(l3, SAMPLES, res, 2000);

    for (int j = 0; j < SAMPLES; j++) {
      printf("%4d ", (int16_t)res[j]);
    }
    putchar('\n');
  }

  free(res);
  */
}