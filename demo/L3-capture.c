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

#include <mastik/util.h>
#include <mastik/l3.h>

// Define the number of samples (probe repetitions) to collect.
#define SAMPLES 1000


int main(int ac, char **av) {
  // A brief delay to allow the system to stabilize before starting the attack.
  delayloop(3000000000U);

  // === SETUP PHASE ===
  // Prepare the L3 Prime+Probe environment. This is a crucial step that:
  // 1. Allocates a large buffer of memory.
  // 2. Analyzes the CPU's cache geometry to understand how memory addresses map to L3 cache sets and slices.
  // 3. Creates "eviction sets" - groups of memory addresses that all map to the same cache set.
  l3pp_t l3 = l3_prepare(NULL, NULL);

  // Get the total number of L3 cache sets discovered by the preparation phase.
  int nsets = l3_getSets(l3);
  
  // We will not monitor every single cache set, as this would be slow.
  // Instead, we will monitor a subset of them, spaced out to cover different cache slices.
  // Here, we choose to monitor one set out of every 64.
  int nmonitored = nsets/64;

  // This loop selects which specific cache sets to spy on.
  // It starts at set 17 and jumps by 64 each time.
  for (int i = 17; i < nsets; i += 64)
    l3_monitor(l3, i);


  // === ATTACK PHASE ===
  // Allocate memory to store the results of our probes.
  // The size is the number of samples multiplied by the number of sets we are monitoring.
  uint16_t *res = calloc(SAMPLES * nmonitored, sizeof(uint16_t));

  // Touch the first element of each page in the results buffer.
  // This is a performance optimization to ensure the memory is physically allocated by the OS before the attack begins.
  for (int i = 0; i < SAMPLES * nmonitored; i+= 4096/sizeof(uint16_t))
    res[i] = 1;
  
  // This is the core of the attack. It repeatedly performs the Prime+Probe loop for SAMPLES iterations.
  // For each iteration, it will:
  // 1. PRIME: Access all memory lines in the eviction sets for the monitored cache sets, filling them with our data.
  // 2. WAIT: A brief, controlled delay (the 'slot' parameter, here 0 for continuous probing).
  // 3. PROBE: Time how long it takes to access one line from each eviction set again.
  // The timing results (in CPU cycles) are stored in the 'res' array.
  l3_repeatedprobe(l3, SAMPLES, res, 0);


  // === OUTPUT PHASE ===
  // This section prints the collected timing data to the console.
  // Each row corresponds to one sample (one round of probing).
  // Each column corresponds to a different monitored cache set.
  printf("// --- L3 Prime+Probe Timing Data --- //\n");
  printf("// Each row is a single probe round (sample).\n");
  printf("// Each column is a different monitored L3 cache set.\n");
  printf("// Low values (e.g., < 140 cycles) indicate a CACHE HIT (no contention).\n");
  printf("// High values (e.g., > 140 cycles) indicate a CACHE MISS (contention detected).\n");
  printf("// ------------------------------------ //\n");
  
  for (int i = 0; i < SAMPLES; i++) {
    // Print the sample number for clarity.
    printf("Sample %-4d: ", i);
    for (int j = 0; j < nmonitored; j++) {
      // Print the access time for each monitored set, formatted to 4 characters.
      printf("%4d ", res[i*nmonitored + j]);
    }
    // Newline after each sample.
    putchar('\n');
  }

  // === CLEANUP PHASE ===
  // Free the memory we allocated for the results.
  free(res);
  // Release all resources used by the Mastik L3 library.
  l3_release(l3);
}