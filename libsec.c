#include <bsd/stdlib.h>
#include <string.h>
#include <regex.h> 
#include <stdio.h>

#include "libsec.h"

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

static const char charset[] = "azertyuiopqsdfghjklmwxcvbnAZERTYUPQSDFGHJKLMWXCVBN0123456789/*-+:?!#@";

int have_atlo_lower(const char *candidate);
int have_atlo_upder(const char *candidate);
int have_atlo_num(const char *candidate);
unsigned int levenshtein(const char *s1, const char *s2);
unsigned int levenshtein_wordlist(const char *candidate, const char* wordlist);
int common_typo(const char* candidate);

int check_password(const char *candidate) {
    if (candidate == NULL || *candidate == '\0') {
        return -1;
    }
    
    if (strlen(candidate) < 8) {
        return -2;
    }

    if (have_atlo_lower(candidate) || have_atlo_upder(candidate) || have_atlo_num(candidate)) {
        return -3;
    }

    if (common_typo(candidate)) {
        return -4;
    }

    if (levenshtein_wordlist(candidate, "./wordlist.txt") <= 3 ) {
        return -5;
    }

    return 0;
}

char *gen_passwd() {
    size_t len = strlen(charset);
    char *candidate = (char *)calloc(10, sizeof(char));
    if (candidate == NULL) {
        return NULL;
    }

    do {
        for(size_t i=0; i < 10; ++i)
        {
            candidate[i] = charset[arc4random_uniform(len)];
        }
    }
    while (check_password(candidate));

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

unsigned int levenshtein(const char *s1, const char *s2) {
    unsigned int s1len, s2len, x, y, lastdiag, olddiag;
    s1len = strlen(s1);
    s2len = strlen(s2);
    unsigned int column[s1len+1];

    for (y = 1; y <= s1len; y++)
        column[y] = y;
    for (x = 1; x <= s2len; x++) {
        column[0] = x;
        for (y = 1, lastdiag = x-1; y <= s1len; y++) {
            olddiag = column[y];
            column[y] = MIN3(column[y] + 1, column[y-1] + 1, lastdiag + (s1[y-1] == s2[x-1] ? 0 : 1));
            lastdiag = olddiag;
        }
    }
    return(column[s1len]);
}

unsigned int levenshtein_wordlist(const char *candidate, const char *wordlist) {
    FILE *fd = fopen(wordlist, "r");
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

int common_typo(const char* candidate) {
    regex_t regex;
    
    if (regcomp(&regex, "^[A-Z][a-z]*[0-9]*[0-9]$", 0)) {
        return -1;
    }

    if (regexec(&regex, candidate, 0, NULL, 0) == 0) {
        return -2;
    }

    return 0;
}