/**
 * jsmn.c — compilation shim for jsmn single-header JSON parser
 *
 * jsmn is a header-only library; this file provides the one
 * translation unit that defines the implementation so CMake can
 * build it as a static library (libjsmn.a).
 *
 * Download jsmn.h from:
 *   https://raw.githubusercontent.com/zserge/jsmn/master/jsmn.h
 * Place it in the same directory as this file.
 */

#define JSMN_IMPLEMENTATION
#include "jsmn.h"
