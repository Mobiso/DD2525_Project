#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

void abort_(const char *s) {
    fprintf(stderr, "%s\n", s);
    exit(1);
}

/* Simple pixel modification: invert RGB */
void process_pixels(png_bytep *row_pointers, int width, int height) {
    for (int y = 0; y < height; y++) {
        png_bytep row = row_pointers[y];
        for (int x = 0; x < width * 4; x += 4) {
            row[x]     = 255 - row[x];     // R
            row[x + 1] = 255 - row[x + 1]; // G
            row[x + 2] = 255 - row[x + 2]; // B
            // alpha unchanged
        }
    }
}

/* Read metadata text chunks */
void read_text_chunks(png_structp png, png_infop info) {
    int num_text;
    png_textp text_ptr;

    if (png_get_text(png, info, &text_ptr, &num_text)) {
        printf("Metadata (tEXt/iTXt):\n");
        for (int i = 0; i < num_text; i++) {
            printf("  %s = %s\n", text_ptr[i].key, text_ptr[i].text);
        }
    } else {
        printf("No standard text metadata found.\n");
    }
}

/* Read unknown ancillary chunks */
void read_unknown_chunks(png_structp png) {
    png_unknown_chunkp unknowns;
    int count;

    if (png_get_unknown_chunks(png, NULL, &unknowns) == 0) {
        printf("No unknown chunks found (or not enabled).\n");
        return;
    }

    printf("Unknown/ancillary chunks:\n");
    for (count = 0; unknowns[count].name[0]; count++) {
        printf("  Chunk: %.4s size=%u\n",
               unknowns[count].name,
               unknowns[count].size);
    }
}

/* Main processing */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s input.png output.png\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];

    FILE *fp = fopen(input_file, "rb");
    if (!fp) abort_("Cannot open input file");

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) abort_("png_create_read_struct failed");

    png_infop info = png_create_info_struct(png);
    if (!info) abort_("png_create_info_struct failed");

    if (setjmp(png_jmpbuf(png))) abort_("PNG read error");

    png_init_io(png, fp);
    png_read_info(png, info);

    int width = png_get_image_width(png, info);
    int height = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth  = png_get_bit_depth(png, info);

    // Convert to RGBA for simpler manipulation
    if (bit_depth == 16) png_set_strip_16(png);
    if (color_type == PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8) png_set_expand_gray_1_2_4_to_8(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_RGB ||
        color_type == PNG_COLOR_TYPE_GRAY ||
        color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_filler(png, 0xFF, PNG_FILLER_AFTER);

    png_read_update_info(png, info);

    png_bytep *row_pointers = (png_bytep *)malloc(sizeof(png_bytep) * height);
    for (int y = 0; y < height; y++) {
        row_pointers[y] = (png_byte *)malloc(png_get_rowbytes(png, info));
    }

    png_read_image(png, row_pointers);
    fclose(fp);

    /* --- READ METADATA --- */
    read_text_chunks(png, info);

    /* --- READ UNKNOWN CHUNKS --- */
    read_unknown_chunks(png);

    /* --- MODIFY IMAGE --- */
    process_pixels(row_pointers, width, height);

    /* --- WRITE OUTPUT --- */
    FILE *out = fopen(output_file, "wb");
    if (!out) abort_("Cannot open output file");

    png_structp png_out = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_out) abort_("png_create_write_struct failed");

    png_infop info_out = png_create_info_struct(png_out);
    if (!info_out) abort_("png_create_info_struct failed");

    if (setjmp(png_jmpbuf(png_out))) abort_("PNG write error");

    png_init_io(png_out, out);

    png_set_IHDR(
        png_out,
        info_out,
        width,
        height,
        8,
        PNG_COLOR_TYPE_RGBA,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT
    );

    /* --- REWRITE METADATA --- */
    png_text text;
    char new_comment[] = "Processed by custom PNG tool (inversion applied)";

    text.compression = PNG_TEXT_COMPRESSION_NONE;
    text.key = "Comment";
    text.text = new_comment;

    png_set_text(png_out, info_out, &text, 1);

    /* Preserve unknown chunks if needed */
    png_set_unknown_chunks(png_out, info_out, NULL, 0);

    png_write_info(png_out, info_out);
    png_write_image(png_out, row_pointers);
    png_write_end(png_out, NULL);

    fclose(out);

    /* cleanup */
    for (int y = 0; y < height; y++) free(row_pointers[y]);
    free(row_pointers);

    png_destroy_read_struct(&png, &info, NULL);
    png_destroy_write_struct(&png_out, &info_out);

    printf("Done: %s -> %s\n", input_file, output_file);
    return 0;
}