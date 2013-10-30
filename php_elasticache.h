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
#include <sys/time.h>

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
    HashTable      *endpoints;
    char           *raw_endpoints;
    long            new_endpoints;
    long            endpoint_refresh_interval;
    long            endpoint_refresh_timeout;
    struct timespec endpoint_last_refresh;
ZEND_END_MODULE_GLOBALS(elasticache)

#ifdef ZTS
#define EC_G(v) TSRMG(elasticache_globals_id, zend_elasticache_globals *, v)
#else
#define EC_G(v) (elasticache_globals.v)
#endif

typedef struct elasticache_url {
    char *scheme;
    char *user;
    char *pass;
    char *host;
    unsigned short port;
    char *path;
    char *query;
    char *fragment;
} elasticache_url;

PHP_RINIT_FUNCTION(elasticache);
PHP_RSHUTDOWN_FUNCTION(elasticache);
PHP_MINIT_FUNCTION(elasticache);
PHP_MSHUTDOWN_FUNCTION(elasticache);
PHP_MINFO_FUNCTION(elasticache);

static void elasticache_debug(const char *format, ...);
static void elasticache_init_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC);
static void elasticache_destroy_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC);
static struct timeval _convert_ms_to_tv(long ms);
static int elasticache_should_refresh(TSRMLS_D);
static void elasticache_parse_endpoints(char *endpoints TSRMLS_DC);
static void elasticache_update(TSRMLS_D);
static zval *elasticache_grab_configuration(char *endpointName, char *endpoint, int endpoint_len, char *errmsg TSRMLS_DC);
static zval *elasticache_parse_nodes(char *response, int response_len, int *node_count);
static int elasticache_sendcmd(php_stream *stream, char *cmd TSRMLS_DC);
static int elasticache_read_value(php_stream *stream, char *buf, int buf_len, char **value, int *value_len TSRMLS_DC);
static int elasticache_readline(php_stream *stream, char *buf, int buf_len TSRMLS_DC);
static int elasticache_parse_response(char *response, int response_len, char **key, int *key_len, int *flags, int *value_len);
static int elasticache_str_left(char *haystack, char *needle, int haystack_len, int needle_len);
static void elasticache_free_url(elasticache_url *url);
static char *elasticache_replace_controlchars(char *str, int len);
static elasticache_url *elasticache_parse_url(char *s);

#endif /* PHP_ELASTICACHE_H */
