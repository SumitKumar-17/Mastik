#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <mastik/fr.h>
#include <mastik/util.h>

// This is our "victim" function. We will spy on it.
void __attribute__ ((noinline)) victim_function() {
  asm volatile("nop");
}

int main(int ac, char **av) {
  // Check for the correct number of arguments
  if (ac != 2) {
    printf("Usage: %s <threshold>\n", av[0]);
    return 1;
  }
  // Convert the threshold argument from text to an integer
  int threshold = atoi(av[1]);
  printf("Using threshold: %d\n", threshold);

  // Prepare the Flush+Reload data structure
  fr_t fr = fr_prepare();
  if (fr == NULL) {
      printf("Failed to prepare FR.\n");
      return 1;
  }

  // Tell Mastik to monitor the memory address of our victim function
  fr_monitor(fr, &victim_function);
  printf("Monitoring victim_function() at address: %p\n", &victim_function);
  
  uint16_t res[1];
  int lines = 0;

  printf("\nStarting probe loop. Press Ctrl+C to stop.\n");
  printf("-----------------------------------------\n");

  for (;;) {
    // Call the victim function so the attacker has something to detect
    victim_function();

    // Now, probe it!
    fr_probe(fr, res);

    // If the probe time is less than our threshold, it's a HIT!
    if (res[0] < threshold) {
      printf("HIT!  Probe time: %4u (Cache Hit)\n", res[0]);
    } else {
      printf("MISS! Probe time: %4u (Cache Miss)\n", res[0]);
    }

    // Wait a bit before the next loop
    delayloop(5000000);
  }

  // Clean up when done (though this loop runs forever)
  fr_release(fr);
  return 0;
}