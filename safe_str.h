#ifndef __RK_SAFE_STR__
#include <linux/slab.h>

#pragma GCC push_options
#pragma GCC optimize ("O0")

char *safe_str(char *buf, int len, char *key, int key_len) {
    int i = 0;
    char *ret = kmalloc(sizeof(char) * (len + 1), GFP_KERNEL);
    ret[len] = '\0';
    for (;i < len; i++) {
        ret[i] = buf[i] ^ key[i % key_len];
    }
    return ret;
}

#pragma GCC pop_options
#define __RK_SAFE_STR__
#endif
