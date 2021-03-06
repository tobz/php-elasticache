/*
  +----------------------------------------------------------------------------------+
  | Permission is hereby granted, free of charge, to any person obtaining a copy of  |
  | this software and associated documentation files (the "Software"), to deal in    |
  | the Software without restriction, including without limitation the rights to     |
  | use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of |
  | the Software, and to permit persons to whom the Software is furnished to do so,  |
  | subject to the following conditions:                                             |
  |                                                                                  |
  | The above copyright notice and this permission notice shall be included in all   |
  | copies or substantial portions of the Software.                                  |
  |                                                                                  |
  | THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR       |
  | IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS |
  | FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR   |
  | COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER   |
  | IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN          |
  | CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.       |
  +----------------------------------------------------------------------------------+
  | Authors: Toby Lawrence <toby@bluestatedigital.com>                               |
  +----------------------------------------------------------------------------------+
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

typedef struct elasticache_endpoint {
    char *scheme;
    char *user;
    char *pass;
    char *host;
    unsigned short port;
    char *path;
    char *query;
    char *fragment;
} elasticache_endpoint;

typedef struct elasticache_cluster {
    elasticache_endpoint **nodes;
    int nodeCount;
} elasticache_cluster;

/*
 * Define our globals and helper macros to access them.
 */
ZEND_BEGIN_MODULE_GLOBALS(elasticache)
    char *rawEndpoints;
    long endpointRefreshTimeout;
ZEND_END_MODULE_GLOBALS(elasticache)

#ifdef ZTS
#define EC_G(v) TSRMG(elasticache_globals_id, zend_elasticache_globals *, v)
#else
#define EC_G(v) (elasticache_globals.v)
#endif

#if defined(__GNUC__) || (defined(__MWERKS__) && (__MWERKS__ >= 0x3000)) || (defined(__ICC) && (__ICC >= 600))
# define CFN __PRETTY_FUNCTION__
#elif defined(__DMC__) && (__DMC__ >= 0x810)
# define CFN __PRETTY_FUNCTION__
#elif defined(__FUNCSIG__)
# define CFN __FUNCSIG__
#elif (defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 600)) || (defined(__IBMCPP__) && (__IBMCPP__ >= 500))
# define CFN __FUNCTION__
#elif defined(__BORLANDC__) && (__BORLANDC__ >= 0x550)
# define CFN __FUNC__
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901)
# define CFN __func__
#else
# define CFN "(unknown)"
#endif

PHP_RINIT_FUNCTION(elasticache);
PHP_RSHUTDOWN_FUNCTION(elasticache);
PHP_MINIT_FUNCTION(elasticache);
PHP_MSHUTDOWN_FUNCTION(elasticache);
PHP_MINFO_FUNCTION(elasticache);

static void elasticache_debug(const char *format, ...);
static void elasticache_init_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC);
static void elasticache_destroy_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC);
static int elasticache_parse_endpoints(elasticache_endpoint ***endpoints TSRMLS_DC);
static void elasticache_update(TSRMLS_D);
static elasticache_cluster* elasticache_get_cluster(elasticache_endpoint *endpoint, char *errmsg TSRMLS_DC);
static int elasticache_parse_config(char *response, int responseLen, elasticache_cluster *cluster);
static int elasticache_sendcmd(php_stream *stream, char *cmd TSRMLS_DC);
static int elasticache_read_value(php_stream *stream, char *buf, int buf_len, char **value, int *value_len TSRMLS_DC);
static int elasticache_readline(php_stream *stream, char *buf, int buf_len TSRMLS_DC);
static int elasticache_parse_response(char *response, int response_len, char **key, int *key_len, int *flags, int *value_len);
static int elasticache_str_left(char *haystack, char *needle, int haystack_len, int needle_len);
static void elasticache_free_endpoint(elasticache_endpoint *url);
static void elasticache_free_cluster(elasticache_cluster *cluster);
static char* elasticache_replace_controlchars(char *str, int len);
static elasticache_endpoint *elasticache_parse_endpoint(char *s);

#endif /* PHP_ELASTICACHE_H */
