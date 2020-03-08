#ifndef GEOHASH_H
#define GEOHASH_H

#ifdef __cplusplus
extern "C" {
#endif

// encode geohash
// return malloc'd string, NULL means error
// precision: geohash string len
// precison  = 4 ->  20 km
// precision = 5 -> 2.4 km
// precision = 6 -> 610 m
// precision = 7 ->  76 m
char* geohash_encode(double lat, double lon, int precision);


#ifdef __cplusplus
}
#endif

#endif // GEOHASH_H
