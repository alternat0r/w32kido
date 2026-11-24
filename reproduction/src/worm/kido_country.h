/* Auto-generated: country -> language groups (23), recovered from the worm @RVA 0x153E0. */
/* target_language(): scan groups in order; return the group's lang when the target's 2-letter */
/* country code is listed.  Unknown country -> 9 (English).  'UA' -> 0 (Ukraine excluded). */
/* Only 0x0804 (zh-CN) and 0x0416 (pt-BR) keep the full LANGID; others are primary ids. */
#ifndef KIDO_COUNTRY_H
#define KIDO_COUNTRY_H
#include <stdint.h>
typedef struct { int lang; const char* cc; } kido_cc_t;
static const kido_cc_t g_grp0[] = {
    { 0x0001, "AE" },
    { 0x0001, "BH" },
    { 0x0001, "DZ" },
    { 0x0001, "EG" },
    { 0x0001, "IQ" },
    { 0x0001, "IR" },
    { 0x0001, "KW" },
    { 0x0001, "LB" },
    { 0x0001, "LY" },
    { 0x0001, "MA" },
    { 0x0001, "MR" },
    { 0x0001, "OM" },
    { 0x0001, "QA" },
    { 0x0001, "SA" },
    { 0x0001, "SD" },
    { 0x0001, "SY" },
    { 0x0001, "TN" },
    { 0x0001, "YE" },
    { 0, NULL }
};
static const kido_cc_t g_grp1[] = {
    { 0x0416, "BR" },
    { 0, NULL }
};
static const kido_cc_t g_grp2[] = {
    { 0x0804, "CN" },
    { 0, NULL }
};
static const kido_cc_t g_grp3[] = {
    { 0x0004, "HK" },
    { 0x0004, "MO" },
    { 0x0004, "SG" },
    { 0x0004, "TW" },
    { 0, NULL }
};
static const kido_cc_t g_grp4[] = {
    { 0x0005, "CZ" },
    { 0, NULL }
};
static const kido_cc_t g_grp5[] = {
    { 0x0006, "DK" },
    { 0, NULL }
};
static const kido_cc_t g_grp6[] = {
    { 0x0013, "AN" },
    { 0x0013, "AW" },
    { 0x0013, "BE" },
    { 0x0013, "NL" },
    { 0x0013, "SM" },
    { 0, NULL }
};
static const kido_cc_t g_grp7[] = {
    { 0x000B, "FI" },
    { 0, NULL }
};
static const kido_cc_t g_grp8[] = {
    { 0x000C, "FR" },
    { 0x000C, "GF" },
    { 0x000C, "PF" },
    { 0x000C, "TF" },
    { 0x000C, "PM" },
    { 0x000C, "RE" },
    { 0x000C, "WF" },
    { 0x000C, "YT" },
    { 0x000C, "CI" },
    { 0x000C, "BF" },
    { 0x000C, "BI" },
    { 0x000C, "BJ" },
    { 0x000C, "CD" },
    { 0x000C, "CM" },
    { 0x000C, "DJ" },
    { 0x000C, "GA" },
    { 0x000C, "GN" },
    { 0x000C, "GP" },
    { 0x000C, "HT" },
    { 0x000C, "MG" },
    { 0x000C, "MQ" },
    { 0x000C, "MS" },
    { 0x000C, "NC" },
    { 0x000C, "NE" },
    { 0x000C, "PM" },
    { 0x000C, "SN" },
    { 0x000C, "ST" },
    { 0x000C, "TD" },
    { 0x000C, "TG" },
    { 0x000C, "WF" },
    { 0x000C, "YT" },
    { 0, NULL }
};
static const kido_cc_t g_grp9[] = {
    { 0x0007, "AT" },
    { 0x0007, "DE" },
    { 0x0007, "CH" },
    { 0x0007, "LU" },
    { 0x0007, "LI" },
    { 0, NULL }
};
static const kido_cc_t g_grp10[] = {
    { 0x0008, "CY" },
    { 0x0008, "GR" },
    { 0, NULL }
};
static const kido_cc_t g_grp11[] = {
    { 0x000E, "HU" },
    { 0, NULL }
};
static const kido_cc_t g_grp12[] = {
    { 0x000D, "IL" },
    { 0, NULL }
};
static const kido_cc_t g_grp13[] = {
    { 0x0010, "IT" },
    { 0x0010, "SM" },
    { 0x0010, "VA" },
    { 0, NULL }
};
static const kido_cc_t g_grp14[] = {
    { 0x0011, "JP" },
    { 0, NULL }
};
static const kido_cc_t g_grp15[] = {
    { 0x0012, "KP" },
    { 0x0012, "KR" },
    { 0, NULL }
};
static const kido_cc_t g_grp16[] = {
    { 0x0014, "BV" },
    { 0x0014, "NO" },
    { 0x0014, "SJ" },
    { 0, NULL }
};
static const kido_cc_t g_grp17[] = {
    { 0x0015, "PL" },
    { 0, NULL }
};
static const kido_cc_t g_grp18[] = {
    { 0x0016, "AN" },
    { 0x0016, "CV" },
    { 0x0016, "GW" },
    { 0x0016, "MZ" },
    { 0x0016, "PT" },
    { 0x0016, "TL" },
    { 0x0016, "TP" },
    { 0, NULL }
};
static const kido_cc_t g_grp19[] = {
    { 0x0019, "BY" },
    { 0x0019, "KG" },
    { 0x0019, "KZ" },
    { 0x0019, "MD" },
    { 0x0019, "RU" },
    { 0x0019, "SU" },
    { 0x0019, "TJ" },
    { 0x0019, "TM" },
    { 0x0019, "UA" },
    { 0x0019, "UZ" },
    { 0, NULL }
};
static const kido_cc_t g_grp20[] = {
    { 0x000A, "AD" },
    { 0x000A, "AR" },
    { 0x000A, "BO" },
    { 0x000A, "CL" },
    { 0x000A, "CO" },
    { 0x000A, "CR" },
    { 0x000A, "CU" },
    { 0x000A, "EC" },
    { 0x000A, "ES" },
    { 0x000A, "GT" },
    { 0x000A, "GD" },
    { 0x000A, "HN" },
    { 0x000A, "MX" },
    { 0x000A, "NI" },
    { 0x000A, "PA" },
    { 0x000A, "PE" },
    { 0x000A, "PY" },
    { 0x000A, "SV" },
    { 0x000A, "VE" },
    { 0, NULL }
};
static const kido_cc_t g_grp21[] = {
    { 0x001D, "AX" },
    { 0x001D, "SE" },
    { 0, NULL }
};
static const kido_cc_t g_grp22[] = {
    { 0x001F, "TR" },
    { 0, NULL }
};
static const kido_cc_t* const g_country_groups[23] = {
    g_grp0,
    g_grp1,
    g_grp2,
    g_grp3,
    g_grp4,
    g_grp5,
    g_grp6,
    g_grp7,
    g_grp8,
    g_grp9,
    g_grp10,
    g_grp11,
    g_grp12,
    g_grp13,
    g_grp14,
    g_grp15,
    g_grp16,
    g_grp17,
    g_grp18,
    g_grp19,
    g_grp20,
    g_grp21,
    g_grp22,
};
#define KIDO_COUNTRY_GROUPS 23
#endif
