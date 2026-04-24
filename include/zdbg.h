/*
 * zdbg.h - common base definitions for zdbg.
 *
 * Keep this header intentionally small.  Only the types and
 * constants that are shared by every other module belong here.
 */

#ifndef ZDBG_H
#define ZDBG_H

#include <stdint.h>
#include <stddef.h>

#define ZDBG_VERSION_MAJOR 0
#define ZDBG_VERSION_MINOR 1

#define ZDBG_OK  0
#define ZDBG_ERR (-1)

typedef uint64_t zaddr_t;

#endif /* ZDBG_H */
