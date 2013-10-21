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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <php.h>
#include <php_main.h>

#ifdef ZTS
#include "TSRM.h"
#endif

#include "ext/standard/info.h"
#include "php_elasticache.h"

ZEND_DECLARE_MODULE_GLOBALS(elasticache)

/* {{{ INI entries */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("elasticache.endpoints", "", PHP_INI_ALL, OnUpdateString, endpoints, zend_elasticache_globals, elasticache_globals)
    STD_PHP_INI_ENTRY("elasticache.endpoint_refresh_interval", "1000", PHP_INI_ALL, OnUpdateLong, endpoint_refresh_interval, zend_elasticache_globals, elasticache_globals)
    STD_PHP_INI_ENTRY("elasticache.endpoint_refresh_timeout", "250", PHP_INI_ALL, OnUpdateLong, endpoint_refresh_timeout, zend_elasticache_globals, elasticache_globals)
PHP_INI_END()
/* }}} */

/* {{{ proto string elasticache_version()
	Returns the elasticache version
*/
PHP_FUNCTION(elasticache_version)
{
	/* The function takes no arguments */
	if(zend_parse_parameters_none() == FAILURE) {
		return;
	}

	/* Return a string, the second parameter implicates whether to copy the 
		string or not. In general you would copy everything that is not allocated
		with emalloc or similar because the value is later efreed
	*/
	RETURN_STRING(PHP_ELASTICACHE_EXTVER, 1);
}
/* }}} */

PHP_RINIT_FUNCTION(elasticache)
{
	/*
		Do any per request initialisation here. Not used commonly
		and also note that doing heavy processing here will affect
		every request. If possible it's always better to use MINIT
	*/
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(elasticache)
{
	/*
		Executed during request shutdown
	*/
	return SUCCESS;
}

/* Compatibility macro for pre PHP 5.4 versions to initialise properties */
#if PHP_VERSION_ID < 50399 && !defined(object_properties_init)
# define object_properties_init(zo, class_type) { \
			zval *tmp; \
			zend_hash_copy((*zo).properties, \
							&class_type->default_properties, \
							(copy_ctor_func_t) zval_add_ref, \
							(void *) &tmp, \
							sizeof(zval *)); \
		 }
#endif

static void elasticache_init_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC)
{
    EC_G(endpoints) = NULL;
    EC_G(endpoint_refresh_interval) = 1000;
    EC_G(endpoint_refresh_timeout) = 250;
    EC_G(endpoint_last_refresh) = 0;
}

static void elasticache_destroy_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC)
{
}

PHP_MINIT_FUNCTION(elasticache)
{
#ifdef ZTS
    ts_allocate_id(&elasticache_globals_id, sizeof(zend_elasticache_globals),
        (ts_allocate_ctor) elasticache_init_globals, (ts_allocate_dtor) elasticache_destroy_globals);
#else
    elasticache_init_globals(&elasticache_globals TSRMLS_CC);
#endif

    REGISTER_INI_ENTRIES();

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(elasticache)
{
#ifdef ZTS
    ts_free_id(elasticache_globals_id);
#else
    elasticache_destroy_globals(&elasticache_globals TSRMLS_CC);
#endif

    UNREGISTER_INI_ENTRIES();

	return SUCCESS;
}

/*
	This function gets executed during phpinfo to display information about the extension.
	There is a correspending PHP_INFO(elasticache) entry in the elasticache_module_entry
*/
PHP_MINFO_FUNCTION(elasticache)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "elasticache extension", "enabled");
    php_info_print_table_row(2, "elasticache extension version", PHP_ELASTICACHE_EXTVER);
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

ZEND_BEGIN_ARG_INFO_EX(elasticache_version_args, 0, 0, 0)
ZEND_END_ARG_INFO()

/*
  Functions that the extension provides, class methods are separately
*/
zend_function_entry elasticache_functions[] = {
	PHP_FE(elasticache_version, elasticache_version_args)
	/* Add more PHP_FE entries here, the last entry needs to be NULL, NULL, NULL */
	{NULL, NULL, NULL}
};

/**
 The standard module structure for PHP extension
 RINIT and RSHUTDOWN can be NULL if there is nothing to do during request startup / shutdown
*/
zend_module_entry elasticache_module_entry =
{
	STANDARD_MODULE_HEADER,
	"elasticache"					/* Name of the extension */,
	elasticache_functions,		/* This is where you would functions that are not part of classes */
	PHP_MINIT(elasticache),		/* Executed once during module initialisation, not per request */
	PHP_MSHUTDOWN(elasticache),	/* Executed once during module shutdown, not per request */
	PHP_RINIT(elasticache),		/* Executed every request, before script is executed */
	PHP_RSHUTDOWN(elasticache),	/* Executed every request, after script has executed */
	PHP_MINFO(elasticache),		/* Hook for displaying info in phpinfo() */
	PHP_ELASTICACHE_EXTVER,		/* Extension version, defined in php_elasticache.h */
	STANDARD_MODULE_PROPERTIES
};

/*
  See definition of ZEND_GET_MODULE in zend_API.h around line 133
  Expands into get_module call which returns the zend_module_entry
*/
#ifdef COMPILE_DL_ELASTICACHE
ZEND_GET_MODULE(elasticache)
#endif /* COMPILE_DL_ELASTICACHE */
