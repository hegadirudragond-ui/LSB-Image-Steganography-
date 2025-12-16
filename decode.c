/*-------------------------------------------------------------------------------------
  File Name     : decode.c
  Description   : reverse point for the LSB Image Steganography project. 
                  This file controls decoding  operations in LSB part.
                  for hiding secret information within stego images.
  Project Title : LSB Image Steganography(decoding part)
  Name          : Rudragond Hegadi
  Date          : 3/11/2025
 ------------------------------------------------------------------------------------*/#include <stdio.h>
#include <stdlib.h>
#include "typesd.h"
#include <string.h>
#include "common.h"
#include "decode.h"

// Read and validate decoding arguments
d_Status read_and_validate_decode_args(int argc, char *argv[], DecodeInfod *decInfo)
{
    if (argc < 3) return d_failure;                  // Need at least: ./a.out -d <stego.bmp>
    if (strstr(argv[2], ".bmp") == NULL) return d_failure; // Ensure BMP file
    decInfo->stego_image_fname = argv[2];

    decInfo->fptr_stego_image = fopen(decInfo->stego_image_fname, "rb"); // Open image
    if (decInfo->fptr_stego_image == NULL) { perror("fopen"); return d_failure; }

    // Optional output filename
    if (argc == 4) strcpy(decInfo->buffer, strtok(argv[3], ".")); 
    else strcpy(decInfo->buffer, "output");

    return d_success;
}

// Decode and verify magic string
d_Status decode_magic_string(char *magic_string, DecodeInfod *decInfo)
{
    char image[8];
    int size = strlen(MAGIC_STRING);

    for (int i = 0; i < size; i++) {
        fread(image, 1, 8, decInfo->fptr_stego_image);  // Read 8 bytes from image
        decode_byte_from_lsb(&magic_string[i], image);  // Decode one byte
    }

    magic_string[size] = '\0';
    if(strcmp(magic_string, MAGIC_STRING) == 0) {    // Verify magic string
        printf("1. Magic String verified: %s\n", magic_string);
        return d_success;
    }
    return d_failure;
}

// Decode secret file extension size
d_Status decode_secret_file_extn_size(long int *size, DecodeInfod *decInfo)
{
    char image[32];
    fread(image, 1, 32, decInfo->fptr_stego_image);  // Read 32 bytes
    decode_size_from_lsb(size, image);               // Extract size from LSBs
    return d_success;
}

// Decode secret file extension and open output file
d_Status decode_extn(int *size, DecodeInfod *decInfo)
{
    char extension[*size + 1];
    char image[8];

    for(int i = 0; i < *size; i++) {
        fread(image, 1, 8, decInfo->fptr_stego_image); 
        decode_byte_from_lsb(&extension[i], image);   // Decode each extension character
    }

    extension[*size] = '\0';
    strcpy(decInfo->extn_secret_file, extension);
    if (decInfo->buffer != NULL) strcat(decInfo->buffer, extension);

    decInfo->output_fptr = fopen(decInfo->buffer, "wb"); // Create output file
    return d_success;
}

// Decode secret file size
d_Status decode_secret_file_size(long *file_size, DecodeInfod *decodeInfo)
{
    *file_size = 0;
    char image[32];
    fread(image, 1, 32, decodeInfo->fptr_stego_image);  // Read 32 bytes
    decode_size_from_lsb(file_size, image);             // Extract size from LSBs
    return d_success;
}

// Decode secret file data
d_Status decode_secret_file_data(DecodeInfod *decodInfo)
{
    long size = decodInfo->size_secret_file;
    char *secret_data = malloc(size);
    char image_buffer[8];

    for (long i = 0; i < size; i++) {
        fread(image_buffer, 1, 8, decodInfo->fptr_stego_image); 
        decode_byte_from_lsb(&secret_data[i], image_buffer);  // Decode each byte
    }

    fwrite(secret_data, 1, size, decodInfo->output_fptr);   // Write to output file
    fclose(decodInfo->output_fptr);
    free(secret_data);
    return d_success;
}

// Decode a single byte from 8 LSBs
d_Status decode_byte_from_lsb(char *data, char *image_buffer)
{
    *data = 0;
    for(int i = 0; i < 8; i++) *data = (*data << 1) | (image_buffer[i] & 1);
    return d_success;
}

// Decode 32-bit size from LSBs
d_Status decode_size_from_lsb(long int *size, char *imageBuffer)
{
    *size = 0;
    for(int i = 0; i < 32; i++) *size = (*size << 1) | (imageBuffer[i] & 1);
    return d_success;
}

// Main decoding process
d_Status do_decoding(DecodeInfod *decInfo)
{
    fseek(decInfo->fptr_stego_image, 54, SEEK_SET); // Skip BMP header

    char magic_string[strlen(MAGIC_STRING) + 1];
    decode_magic_string(magic_string, decInfo);      // Verify magic string

    long int extn_size;
    decode_secret_file_extn_size(&extn_size, decInfo); 
    decode_extn((int *)&extn_size, decInfo);         // Decode file extension

    decode_secret_file_size(&decInfo->size_secret_file, decInfo); 
    decode_secret_file_data(decInfo);                // Decode secret data

    printf("✅ Decoding completed successfully...\n");                     
    return d_success;
}
