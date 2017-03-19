#include <bsd/stdlib.h>
#include <string.h>
#include <stdio.h>

#include "libsec.h"

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

int have_atlo_lower(const char *candidate);
int have_atlo_upder(const char *candidate);
int have_atlo_num(const char *candidate);
size_t levenshtein(const char *s1, const char *s2);
size_t levenshtein_wordlist(s_sec_settings *settings, const char *candidate);
int common_typo(s_sec_settings *settings, const char* candidate);
int check_settings(s_sec_settings *settings);

s_sec_settings *init_libsec(const char* path) {
    FILE *fd = fopen(path, "r");
    if (fd == NULL) {
        fprintf(stderr, "[LibSec] Could not open %s !\n", path);
        return NULL;
    }

    s_sec_settings *settings = (s_sec_settings *)calloc(1, sizeof(s_sec_settings));
    if (settings == NULL) {
        return NULL;
    }

    char *line = NULL;
    size_t len;
    while(getline(&line, &len, fd) > 1) {
        line[len-1] = '\0';

        char value[128], key[128];
        sscanf(line, "%s = %s", key, value);

        if (strcmp(key, "min_len") == 0) {
            settings->min_len = atol(value);
        } else if (strcmp(key, "gen_len") == 0) {
            settings->gen_len = atol(value);
        } else if (strcmp(key, "charset") == 0) {
            settings->gen_charset = strdup(value);
        } else if (strcmp(key, "wordlist") == 0) {
            settings->wordlist_path = strdup(value);
        } else if (strcmp(key, "levenshtein_distance") == 0) {
            settings->levenshtein_min_distance = atoi(value);
        } else if (strcmp(key, "forbiden_typo") == 0) {
            settings->common_typos = (regex_t *)calloc(1, sizeof(regex_t));
            if (settings->common_typos == NULL) {
                continue;
            }

            if (regcomp(settings->common_typos, value, 0)) {
                fprintf(stderr, "[LibSec] regex compillation error !\n");
                continue;
            }
        } 

        free(line);
        line = NULL;
    }

    if (check_settings(settings)) {
        return NULL;
    }

    return settings;
}

void free_settings(s_sec_settings *settings) {
    if(settings == NULL) return;
    
    if(settings->gen_charset != NULL) {
        free(settings->gen_charset);
        settings->gen_charset = NULL;
    }
    
    if(settings->wordlist_path != NULL) {
        free(settings->wordlist_path);
        settings->wordlist_path = NULL;
    }

    if(settings->common_typos != NULL) {
        regfree(settings->common_typos);
        settings->common_typos = NULL;
    }

    free(settings);
}


int check_password(s_sec_settings *settings, const char *candidate) {
    if (check_settings(settings)) {
        return -1;
    }

    if (candidate == NULL || *candidate == '\0') {
        return -1;
    }
    
    if (strlen(candidate) < settings->min_len) {
        return -2;
    }

    if (have_atlo_lower(candidate) || have_atlo_upder(candidate) || have_atlo_num(candidate)) {
        return -3;
    }

    if (common_typo(settings, candidate)) {
        return -4;
    }

    if (levenshtein_wordlist(settings, candidate) < settings->levenshtein_min_distance ) {
        return -5;
    }

    return 0;
}

char *gen_passwd(s_sec_settings *settings) {
    if (check_settings(settings)) {
        return NULL;
    }

    size_t len = strlen(settings->gen_charset);
    char *candidate = (char *)calloc(settings->gen_len, sizeof(char));
    if (candidate == NULL) {
        return NULL;
    }

    size_t i = 0;
    do {
        for(size_t i=0; i < settings->gen_len; ++i)
        {
            candidate[i] = settings->gen_charset[arc4random_uniform(len)];
        }

        ++i;
    }
    while (check_password(settings, candidate) && i < 10);

    if (i >= 10) {
        fprintf(stderr, "[LibSec] Infinit loop avoid!\n");
        return NULL;
    }

    return candidate;
}

int have_atlo_lower(const char *candidate) {
    for(char *i=(char *)candidate; *i!='\0'; ++i) {
        if (*i >= 'a' && *i <= 'z') return 0;
    }

    return -1;
}

int have_atlo_upder(const char *candidate) {
    for(char *i=(char *)candidate; *i!='\0'; ++i) {
        if (*i >= 'A' && *i <= 'Z') return 0;
    }

    return -1;
}

int have_atlo_num(const char *candidate) {
    for(char *i=(char *)candidate; *i!='\0'; ++i) {
        if (*i >= '0' && *i <= '9') return 0;
    }

    return -1;
}

size_t levenshtein(const char *s1, const char *s2) {
    size_t s1len, s2len, x, y, lastdiag, olddiag;
    s1len = strlen(s1);
    s2len = strlen(s2);
    size_t column[s1len+1];

    for (y = 1; y <= s1len; ++y)
        column[y] = y;
    for (x = 1; x <= s2len; ++x) {
        column[0] = x;
        for (y = 1, lastdiag = x-1; y <= s1len; ++y) {
            olddiag = column[y];
            column[y] = MIN3(column[y] + 1, column[y-1] + 1, lastdiag + (s1[y-1] == s2[x-1] ? 0 : 1));
            lastdiag = olddiag;
        }
    }
    return(column[s1len]);
}

size_t levenshtein_wordlist(s_sec_settings *settings, const char *candidate) {
    FILE *fd = fopen(settings->wordlist_path, "r");
    if (fd == NULL) {
        return 0;
    }

    size_t len;
    char *buffer = NULL;
    unsigned int current = 8;
    while(getline(&buffer, &len, fd) > 1) {
        buffer[len-1] = '\0';

        unsigned int le = levenshtein(buffer, candidate);
        if (le < current) {
            current = le;
        }
        
        free(buffer);
        buffer = NULL;
    }

    return current;
}

int common_typo(s_sec_settings *settings, const char* candidate) {
    if (regexec(settings->common_typos, candidate, 0, NULL, 0) == 0) {
        return -1;
    }

    return 0;
}

int check_settings(s_sec_settings *settings) {
    if (settings == NULL) {
        fprintf(stderr, "[LibSec] Setting not intialized !\n");
        return -1;
    }

    if (settings->min_len > settings->gen_len) {
        fprintf(stderr, "[LibSec] min_len > gen_len !\n");
        return -2;
    }

    if (settings->gen_charset == NULL || *(settings->gen_charset) == '\0') {
        fprintf(stderr, "[LibSec] Charset empty !\n");
        return -3;
    }

    if (settings->wordlist_path == NULL || *(settings->wordlist_path) == '\0') {
        fprintf(stderr, "[LibSec] Wordlist Path empty !\n");
        return -5;
    }

    if (settings->common_typos == NULL) {
        fprintf(stderr, "[LibSec] Bad Regex in common_type !\n");
        return -6;
    }

    return 0;
}