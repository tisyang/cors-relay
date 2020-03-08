#include "geohash.h"
#include <stdlib.h>
#include <math.h>

struct RangeF {
    double high;
    double low;
};

#define SET_BIT(bits, mid, range, value, offset) \
mid = ((range)->high + (range)->low) / 2.0; \
if ((value) >= mid) { \
    (range)->low = mid; \
    (bits) |= (0x1 << (offset)); \
} else { \
    (range)->high = mid; \
    (bits) |= (0x0 << (offset)); \
}

static const char CHAR_MAP[32] =  "0123456789bcdefghjkmnpqrstuvwxyz";

char* geohash_encode(double lat, double lon, int precision)
{
    struct RangeF lat_range = {  90,  -90 };
    struct RangeF lon_range = { 180, -180 };

    if (precision <= 0 || fabs(lat) > 90.0 || fabs(lon) > 180.0) {
        return NULL;
    }

    char* hash = (char *)malloc(precision + 1);
    if (hash == NULL) {
        return NULL;
    }

    double val1 = lon;
    struct RangeF *range1 = &lon_range;
    double val2 = lat;
    struct RangeF *range2 = &lat_range;
    unsigned char bits = 0;
    for (int i = 0; i < precision; i++) {
        double mid;
        bits = 0;
        SET_BIT(bits, mid, range1, val1, 4);
        SET_BIT(bits, mid, range2, val2, 3);
        SET_BIT(bits, mid, range1, val1, 2);
        SET_BIT(bits, mid, range2, val2, 1);
        SET_BIT(bits, mid, range1, val1, 0);

        hash[i] = CHAR_MAP[bits];

        double val_tmp   = val1;
        val1      = val2;
        val2      = val_tmp;
        struct RangeF *range_tmp = range1;
        range1    = range2;
        range2    = range_tmp;
    }
    hash[precision] = '\0';
    return hash;
}
