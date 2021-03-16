/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "string_conversion.h"

#define STR_MAX_CHARACTERS      160
#define STR_7BIT_ESCAPE_IND     0x80
#define STR_7BIT_CODE_MASK      0x7F
#define STR_7BIT_ESCAPE_CODE    0x1B

/* Conversion table from ASCII (with ISO-8859-15 extension) to GSM 7 bit Default
 * Alphabet character set (3GPP TS 23.038 chapter 6.2.1). Table index equals the
 * ASCII character code and the value stored in the index is the corresponding
 * GSM 7 bit character code.
 *
 * Notes:
 * - Use of GSM extension table is marked by setting bit 8 to 1. In that case
 *   the lowest 7 bits indicate character code in the default extension table.
 *   In the resulting 7-bit string that is coded as 2 characters: the "escape
 *   to extension" code 0x1B followed by character code in the default extension
 *   table.
 * - A space character (0x20) is used in case there is no matching or similar
 *   character available in the GSM 7 bit char set.
 * - When possible, closest similar character is used, like plain letters
 *   instead of letters with different accents, if there is no equivalent
 *   character available.
 */
static const uint8_t ascii_to_7bit_table[256] =
{
    /* Standard ASCII, character codes 0-127 */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 0-7:   Control characters */
    0x20, 0x20, 0x0A, 0x20, 0x20, 0x0D, 0x20, 0x20,  /* 8-15:  ...LF,..CR...      */

    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 16-31: Control characters */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,

    0x20, 0x21, 0x22, 0x23, 0x02, 0x25, 0x26, 0x27,  /* 32-39: SP ! " # $ % & ' */
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,  /* 40-47: ( ) * + , - . /  */

    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  /* 48-55: 0 1 2 3 4 5 6 7  */
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,  /* 56-63: 8 9 : ; < = > ?  */

    0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  /* 64-71: @ A B C D E F G  */
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,  /* 72-79: H I J K L M N O  */

    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  /* 80-87: P Q R S T U V W  */
    0x58, 0x59, 0x5A, 0xBC, 0xAF, 0xBE, 0x94, 0x11,  /* 88-95: X Y Z [ \ ] ^ _  */

    0x27, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,  /* 96-103: (` -> ') a b c d e f g */
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,  /* 104-111:h i j k l m n o  */

    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,  /* 112-119: p q r s t u v w  */
    0x78, 0x79, 0x7A, 0xA8, 0xC0, 0xA9, 0xBD, 0x20,  /* 120-127: x y z { | } ~ DEL */

    /* Character codes 128-255 (beyond standard ASCII) have different possible
     * interpretations. This table has been done according to ISO-8859-15. */

    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 128-159: Undefined   */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,

    0x20, 0x40, 0x63, 0x01, 0xE5, 0x03, 0x53, 0x5F,  /* 160-167: ..£, €... */
    0x73, 0x63, 0x20, 0x20, 0x20, 0x2D, 0x20, 0x20,  /* 168-175 */

    0x20, 0x20, 0x20, 0x20, 0x5A, 0x75, 0x0A, 0x20,  /* 176-183 */
    0x7A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x59, 0x60,  /* 184-191 */

    0x41, 0x41, 0x41, 0x41, 0x5B, 0x0E, 0x1C, 0x09,  /* 192-199: ..Ä, Å... */
    0x45, 0x1F, 0x45, 0x45, 0x49, 0x49, 0x49, 0x49,  /* 200-207 */

    0x44, 0x5D, 0x4F, 0x4F, 0x4F, 0x4F, 0x5C, 0x2A,  /* 208-215: ..Ö... */
    0x0B, 0x55, 0x55, 0x55, 0x5E, 0x59, 0x20, 0x1E,  /* 216-223 */

    0x7F, 0x61, 0x61, 0x61, 0x7B, 0x0F, 0x1D, 0x63,  /* 224-231: ..ä, å... */
    0x04, 0x05, 0x65, 0x65, 0x07, 0x69, 0x69, 0x69,  /* 232-239 */

    0x20, 0x7D, 0x08, 0x6F, 0x6F, 0x6F, 0x7C, 0x2F,  /* 240-247: ..ö... */
    0x0C, 0x06, 0x75, 0x75, 0x7E, 0x79, 0x20, 0x79   /* 248-255 */
};


/* Conversion table from GSM 7 bit Default Alphabet character set (3GPP TS
 * 23.038 chapter 6.2.1) to ASCII (with ISO-8859-15 extension). Table index
 * equals the GSM 7 bit character code and the value stored in the index is
 * the corresponding ASCII character code.
 *
 * Notes:
 * - Table indexes 128-255 are used for conversion of characters in GSM default
 *   alphabet extension table, i.e. character codes following the "escape to
 *   extension" code 0x1B.
 * - A space character (0x20) is used in case there is no matching or similar
 *   character available in the ASCII char set, and for the undefined extension
 *   codes.
 */
static const uint8_t gsm7bit_to_ascii_table[256] =
{
    /* GSM 7 bit Default Alphabet table */
    0x40, 0xA3, 0x24, 0xA5, 0xE8, 0xE9, 0xF9, 0xEC,  /*  0- 7: @£$...        */
    0xF2, 0xC7, 0x0A, 0xD8, 0xF8, 0x0D, 0xC5, 0xE5,  /*  8-15: ...LF..CR..Åå */

    0x20, 0x5F, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 16-23: ._...         */
    0x20, 0x20, 0x20, 0x20, 0xC6, 0xE6, 0xDF, 0xC9,  /* 24-31: ..Escape.ÆæßÉ */

    0x20, 0x21, 0x22, 0x23, 0x20, 0x25, 0x26, 0x27,  /* 32-39: Space !"#¤%&' */
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,  /* 40-47: ()*+,-./      */

    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  /* 48-55: 01234567      */
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,  /* 56-63: 89:;<=>?      */

    0xA1, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,  /* 64-71: ¡ABCDEFG      */
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,  /* 72-79: HIJKLMNO      */

    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  /* 80-87: PQRSTUVW      */
    0x58, 0x59, 0x5A, 0xC4, 0xD6, 0xD1, 0xDC, 0xA7,  /* 88-95: XYZÄÖÑÜ§      */

    0xBF, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,  /*  96-103: ¿abcdefg    */
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,  /* 104-111: hijklmno    */

    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,  /* 112-119: pqrstuvw    */
    0x78, 0x79, 0x7A, 0xE4, 0xF6, 0xF1, 0xFC, 0xE0,  /* 120-127: xyzäöñüà    */

    /* GSM 7 bit Default Alphabet extension table:
     * These codes are used for interpreting extended character codes
     * following the "escape" code 0x1B. */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 128-135/ext 0-7      */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 136-143/ext 8-15     */

    0x20, 0x20, 0x20, 0x20, 0x5E, 0x20, 0x20, 0x20,  /* 144-151/ext 16-23  ^ */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 152-159/ext 24-31    */

    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 160-167/ext 32-39    */
    0x7B, 0x7D, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5C,  /* 168-175/ext 40-47 {}\*/

    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 176-183/ext 48-55    */
    0x20, 0x20, 0x20, 0x20, 0x5B, 0x7E, 0x5D, 0x20,  /* 184-191/ext 56-63 [~]*/

    0x7C, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 192-199/ext 64-71 |  */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 200-207/ext 72-79    */

    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 208-215/ext 80-87    */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 216-223/ext 88-95    */

    0x20, 0x20, 0x20, 0x20, 0x20, 0xA4, 0x20, 0x20,  /* 224-231/ext 96-103 € */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 232-239/ext 104-111  */

    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 240-247/ext 112-119  */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  /* 248-255/ext 120-127  */
};

/*********************************************************************************************
 *
 * Function: string_conversion_ascii_to_gsm7bit
 *
 * Description: Convert ASCII characters into GSM 7 bit Default Alphabet character set using
 *              the conversion table (ascii_to_7bit_table). Optionally perform also packing
 *              for the resulting 7 bit string. Note that the 7 bit string may be longer than
 *              the original due to possible extension table usage. Each extended character
 *              needs an escape code in addition to the character code in extension table.
 *
 * References:
 *
 *  3GPP TS 23.038 chapter 6.2.1: GSM 7 bit Default Alphabet
 *
 *
 * Input parameters:
 *
 *  p_data   - Pointer to array of characters to be converted. No null termination.
 *  data_len - Number of characters to be converted, max 160.
 *  packing  - True if the converted 7bit string has to be packed
 *
 *
 * Output parameters:
 *
 *  p_out_data  - Pointer to buffer for the converted string. Shall have allocation
 *                of 160 bytes, or in case of less than 80  input characters, at
 *                least 2*data_len to make sure that buffer overflow will not happen.
 *  p_out_bytes - Pointer to a byte to return number of valid bytes in p_out_data.
 *                May be NULL if not needed.
 *  p_out_chars - Pointer to a byte to return number of 7 bit characters, i.e. septets
 *                (including possible escape characters) in p_out_data. May be NULL if
 *                not needed. Same as p_out_bytes, when packing=false.
 *
 *
 * Return value:
 *
 *  Number of converted characters (same as data_len if all converted successfully).
 *
 *********************************************************************************************/
uint8_t string_conversion_ascii_to_gsm7bit(const uint8_t *p_data,
                                                 uint8_t  data_len,
                                                 uint8_t *p_out_data,
                                                 uint8_t *p_out_bytes,
                                                 uint8_t *p_out_chars,
                                                 bool     packing)
{
    uint8_t i_ascii = 0;
    uint8_t i_7bit = 0;
    uint8_t out_bytes = 0;
    uint8_t char_7bit;
    uint8_t char_ascii;

    if ((p_data != NULL) && (p_out_data != NULL))
    {
        for (i_ascii = 0; i_ascii < data_len; i_ascii++)
        {
            char_ascii = p_data[i_ascii];
            char_7bit = ascii_to_7bit_table[char_ascii];

            if ((char_7bit & STR_7BIT_ESCAPE_IND) == 0)
            {
                /* Character is in default alphabet table */
                if (i_7bit < STR_MAX_CHARACTERS)
                {
                    p_out_data[i_7bit++] = char_7bit;
                }
                else
                {
                    break;
                }
            }
            else
            {
                /* Character is in default extension table */
                if (i_7bit < STR_MAX_CHARACTERS - 1)
                {
                    p_out_data[i_7bit++] = STR_7BIT_ESCAPE_CODE;
                    p_out_data[i_7bit++] = (char_7bit & STR_7BIT_CODE_MASK);
                }
                else
                {
                    break;
                }
            }
        }

        if (packing == true)
        {
            out_bytes = string_conversion_7bit_sms_packing(p_out_data, i_7bit);
        }
        else
        {
            out_bytes = i_7bit;
        }
    }

    if (p_out_bytes != NULL)
    {
        *p_out_bytes = out_bytes;
    }
    if (p_out_chars != NULL)
    {
        *p_out_chars = i_7bit;
    }

    return i_ascii;
}


/*********************************************************************************************
 *
 * Function: string_conversion_gsm7bit_to_ascii
 *
 * Description: Convert GSM 7 bit Default Alphabet characters to ASCII characters using
 *              the conversion table (gsm7bit_to_ascii_table). Perform also unpacking of
 *              the 7 bit string before conversion, if caller indicates that the string is
 *              packed.
 *
 * References:
 *
 *  3GPP TS 23.038 chapter 6.2.1: GSM 7 bit Default Alphabet
 *
 *
 * Input parameters:
 *
 *  p_data   - Pointer to array of characters to be converted. No null termination.
 *  num_char - Number of 7-bit characters to be unpacked, including possible escape codes.
 *             Also indicates maximum allowed number of characters to be stored to output
 *             buffer by this function.
 *  packed   - True if the 7bit string is packed, i.e. has to be unpacked before conversion.
 *
 *
 * Output parameters:
 *
 *  p_out_data - Pointer to buffer for the converted string. Shall have allocation
 *               of at least "num_char" bytes. Note that this function does not add
 *               null termination at the end of the string. It should be done by caller,
 *               when needed. (In that case it could be useful to actually allocate
 *               num_char+1 bytes here.)
 *
 *
 * Return value:
 *
 *  Number of valid bytes/characters in "p_out_data". May be less than "num_char" in the
 *  case that the 7 bit string contains "escape/extended code" sequences, that are converted
 *  to single ASCII characters.
 *
 *********************************************************************************************/
uint8_t string_conversion_gsm7bit_to_ascii(const uint8_t *p_data,
                                                 uint8_t *p_out_data,
                                                 uint8_t  num_char,
                                                 bool     packed)
{
    uint8_t *p_7bit;
    uint8_t i_ascii = 0;
    uint8_t i_7bit = 0;
    uint8_t char_7bit;

    if (packed == true)
    {
        num_char = string_conversion_7bit_sms_unpacking(p_data, p_out_data, num_char);
        p_7bit = p_out_data;
    }
    else
    {
        p_7bit = (uint8_t *)p_data;
    }

    if ((p_data != NULL) && (p_out_data != NULL))
    {
        for (i_7bit = 0; i_7bit < num_char; i_7bit++)
        {
            char_7bit = p_7bit[i_7bit];

            if (char_7bit == STR_7BIT_ESCAPE_CODE)
            {
                i_7bit++;
                if (i_7bit < num_char)
                {
                    char_7bit = p_7bit[i_7bit];
                    p_out_data[i_ascii] = gsm7bit_to_ascii_table[128 + char_7bit];
                }
                else
                {
                    break;
                }
            }
            else
            {
                p_out_data[i_ascii] = gsm7bit_to_ascii_table[char_7bit];
            }

            i_ascii++;
        }
    }

    return i_ascii;
}


/*********************************************************************************************
 *
 * Function: string_conversion_7bit_sms_packing
 *
 * Description: Performs SMS packing for a string using GSM 7 bit character set. The result
 *              is stored in the same memory buffer that contains the input string to be
 *              packed.
 *
 *              Description of the packing functionality:
 *              Unpacked data bits:
 *              bit number:   7   6   5   4   3   2   1   0
 *              data byte 0:  0  1a  1b  1c  1d  1e  1f  1g      d1
 *              data byte 1:  0  2a  3b  2c  2d  2e  2f  2g      d2
 *              data byte 2:  0  3a  3b  3c  3d  3e  3f  3g      d3
 *              and so on...
 *
 *              Packed data bits:
 *              bit number:   7   6   5   4   3   2   1   0
 *              data byte 0: 2g  1a  1b  1c  1d  1e  1f  1g      d1>>0 | d2<<7
 *              data byte 1: 3f  3g  2a  2b  2c  2d  2e  2f      d2>>1 | d3<<6
 *              data byte 2: 4e  4f  4g  3a  3b  3c  3d  3e      d3>>2 | d4<<5
 *              data byte 3: 5d  5e  5f  5g  4a  4b  4c  4d      d4>>3 | d5<<4
 *              data byte 4: 6c  6d  6e  6f  6g  5a  5b  5c      d5>>4 | d6<<3
 *              data byte 5: 7b  7c  7d  7e  7f  7g  6a  6b      d6>>5 | d7<<2
 *              data byte 6: 8a  8b  8c  8d  8e  8f  8g  7a      d7>>6 | d8<<1
 *              data byte 7: Ag  9a  9b  9c  9d  9e  9f  9g      d9>>0 | dA<<7
 *              data byte 8: Bf  Bg  Aa  Ab  Ac  Ad  Ae  Af      dA>>1 | dB<<6
 *              and so on...
 *
 * References:
 *
 *  3GPP TS 23.038 chapter 6.1.2.1: SMS Packing
 *
 *
 * Input parameters:
 *
 *  p_data   - Pointer to array of characters to be packed (no null termination needed).
 *             Also the packed characters are stored into this buffer.
 *  data_len - Number of characters to be packed
 *
 *
 * Output parameters:
 *
 *  p_data   - Pointer to the packed characters (see above).
 *
 *
 * Return value:
 *
 *  Number of valid bytes in the packed character data.
 *
 *********************************************************************************************/
uint8_t string_conversion_7bit_sms_packing(uint8_t *p_data, uint8_t data_len)
{
    uint8_t i_src = 0;
    uint8_t i_dst = 0;
    uint8_t shift = 0;

    if (p_data != NULL)
    {
        while (i_src < data_len)
        {
            p_data[i_dst] = p_data[i_src] >> shift;
            i_src++;

            if (i_src < data_len)
            {
                p_data[i_dst] |= (p_data[i_src] << (7 - shift));
                shift++;

                if (shift == 7)
                {
                    shift = 0;
                    i_src++;
                }
            }
            i_dst++;
        }
    }

    return i_dst;
}


/*********************************************************************************************
 *
 * Function: string_conversion_7bit_sms_unpacking
 *
 * Description: Performs unpacking of a packed GSM 7 bit string as described below.
 *
 *              Packed data bits:
 *              bit number:   7   6   5   4   3   2   1   0
 *              data byte 0: 2g  1a  1b  1c  1d  1e  1f  1g      p0
 *              data byte 1: 3f  3g  2a  2b  2c  2d  2e  2f      p1
 *              data byte 2: 4e  4f  4g  3a  3b  3c  3d  3e      p2
 *              data byte 3: 5d  5e  5f  5g  4a  4b  4c  4d      p3
 *              data byte 4: 6c  6d  6e  6f  6g  5a  5b  5c      p4
 *              data byte 5: 7b  7c  7d  7e  7f  7g  6a  6b      p5
 *              data byte 6: 8a  8b  8c  8d  8e  8f  8g  7a      p6
 *              data byte 7: Ag  9a  9b  9c  9d  9e  9f  9g      p7
 *              data byte 8: Bf  Bg  Aa  Ab  Ac  Ad  Ae  Af      p8
 *              and so on...
 *
 *              Unpacked data bits:
 *              bit number:   7   6   5   4   3   2   1   0
 *              data byte 0:  0  1a  1b  1c  1d  1e  1f  1g       p0 & 7F
 *              data byte 1:  0  2a  3b  2c  2d  2e  2f  2g      (p1 << 1 | p0 >> 7) & 7F
 *              data byte 2:  0  3a  3b  3c  3d  3e  3f  3g      (p2 << 2 | p1 >> 6) & 7F
 *              data byte 3:  0  4a  4b  4c  4d  4e  4f  4g      (p3 << 3 | p2 >> 5) & 7F
 *              data byte 4:  0  5a  5b  5c  5d  5e  5f  5g      (p4 << 4 | p3 >> 4) & 7F
 *              data byte 5:  0  6a  6b  6c  6d  6e  6f  6g      (p5 << 5 | p4 >> 3) & 7F
 *              data byte 6:  0  7a  7b  7c  7d  7e  7f  7g      (p6 << 6 | p5 >> 2) & 7F
 *              data byte 7:  0  8a  8b  8c  8d  8e  8f  8g      (p7 << 7 | p6 >> 1) & 7F
 *              data byte 8:  0  9a  9b  9c  9d  9e  9f  9g      (p7 << 0 | p6 >> 8) & 7F
 *              data byte 9:  0  Aa  Ab  Ac  Ad  Ae  Af  Ag      (p8 << 1 | p7 >> 7) & 7F
 *              data byte A:  0  Ba  Bb  Bc  Bd  Be  Bf  Bg      (p9 << 2 | p8 >> 6) & 7F
 *              and so on...
 *
 *
 * References:
 *
 *  3GPP TS 23.038 chapter 6.1.2.1: SMS Packing
 *
 *
 * Input parameters:
 *
 *  p_packed   - Pointer to buffer containing the packed string.
 *  num_char   - Number of 7-bit characters (i.e. septets) to be unpacked, including
 *               possible escape codes. Also indicates maximum allowed number of
 *               characters to be stored to output buffer by this function.
 *
 * Output parameters:
 *
 *  p_unpacked - Pointer to buffer to store the unpacked string. Allocated size shall be
 *               at least "num_char" bytes.
 *
 *
 * Return value:
 *
 *  Number of valid bytes/characters in the unpacked string "p_unpacked".
 *
 *********************************************************************************************/
uint8_t string_conversion_7bit_sms_unpacking(const uint8_t *p_packed,
                                                   uint8_t *p_unpacked,
                                                   uint8_t  num_char)
{
    uint8_t shift = 1;
    uint8_t i_pack = 1;
    uint8_t i_char = 0;

    if ((p_packed != NULL) && (p_unpacked != NULL) && (num_char > 0))
    {
        p_unpacked[0] = p_packed[0] & STR_7BIT_CODE_MASK;
        i_char++;

        while (i_char < num_char)
        {
            p_unpacked[i_char] = (p_packed[i_pack] << shift) | (p_packed[i_pack - 1] >> (8 - shift));
            p_unpacked[i_char] &= STR_7BIT_CODE_MASK;

            shift++;
            if (shift == 8)
            {
                shift = 0;
            }
            else
            {
                i_pack++;
            }

            i_char++;
        }
    }

    return i_char;
}
