#include <stdlib.h>
#include <stdio.h>

#include "seal.h"
#include "png-util.h"

void encrypt() {

}

void apply_gray() {
  for(int y = 0; y < height; y++) {
    png_bytep row = row_pointers[y];
    for(int x = 0; x < width; x++) {
      png_bytep px = &(row[x * 4]);

      float w_red = 0.2126f;
      float w_green = 0.7152f;
      float w_blue = 0.0722f;

      int gray = (int) (px[0] * w_red + px[1] * w_green + px[2] * w_blue);

      px[0] = gray;
      px[1] = gray;
      px[2] = gray;
      
      row[x * 4] = *px;
    }
    row_pointers[y] = row;
  }
}

void decrypt() {
  
}

int main(int argc, char *argv[]) {
  if(argc != 3) abort();

  read_png_file(argv[1]);
  encrypt();
  apply_gray();
  decrypt();
  write_png_file(argv[2]);

  return 0;
}