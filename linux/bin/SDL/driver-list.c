#include "SDL2/SDL.h"
#include "stdio.h"

int main(int argc, char *argv[]) {
  int i;
  if (SDL_Init(SDL_INIT_AUDIO) < 0) {
    fprintf(stderr, "Couldn't initialize SDL: %s\n", SDL_GetError());
  }
  for (i = 0; i < SDL_GetNumAudioDrivers(); ++i) {
    printf("%s\n", SDL_GetAudioDriver(i));
  }
}
