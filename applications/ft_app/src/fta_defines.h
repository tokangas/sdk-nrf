#ifndef FTA_DEFINES_H
#define FTA_DEFINES_H

#define FTA_EMPTY_STRING "\0"

#define FTA_APN_STR_MAX_LEN (64)
#define FTA_ARG_NOT_SET -6

#define FTA_STRING_NULL_CHECK(string) ((string != NULL) ? string : FTA_EMPTY_STRING)

#endif /* FTA_DEFINES_H */
