#ifndef LIBSEC_H_
#define LIBSEC_H_

#include <regex.h>

typedef struct {
    size_t min_len;
    size_t gen_len;
    char *gen_charset;
    char *wordlist_path;
    size_t levenshtein_min_distance;
    regex_t *common_typos;
} s_sec_settings;

extern s_sec_settings *init_libsec(const char* path);
extern void free_settings(s_sec_settings *settings);
extern int check_password(s_sec_settings *settings, const char *candidate);
extern char *gen_passwd(s_sec_settings *settings);

#endif