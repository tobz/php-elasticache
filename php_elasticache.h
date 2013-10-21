/*
  +----------------------------------------------------------------------+
  | Copyright (c) 2013 The PHP Group                                     |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt.                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: Mikko Koppanen <mkoppanen@php.net>                          |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_ELASTICACHE_H
# define PHP_ELASTICACHE_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"

/*
 * Define the extension version.
 */
#define PHP_ELASTICACHE_EXTVER "0.0.1"

/*
 * Define the extension entry point.
 */
extern zend_module_entry elasticache_module_entry;
#define phpext_elasticache_ptr &elasticache_module_entry

/*
 * Define our globals and helper macros to access them.
 */
ZEND_BEGIN_MODULE_GLOBALS(elasticache)
    char* endpoints;
    long  endpoint_refresh_interval;
    long  endpoint_refresh_timeout;
    long  endpoint_last_refresh;
ZEND_END_MODULE_GLOBALS(elasticache)

#ifdef ZTS
#define EC_G(v) TSRMG(elasticache_globals_id, zend_elasticache_globals *, v)
#else
#define EC_G(v) (elasticache_globals.v)
#endif


#endif /* PHP_ELASTICACHE_H */
