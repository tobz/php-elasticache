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

#include <php_ini.h>
#include <SAPI.h>
#include <ext/standard/info.h>
#include <zend_extensions.h>
#include <zend_exceptions.h>
#include <ext/standard/php_smart_str.h>
#include <ext/standard/php_var.h>
#include <ext/standard/basic_functions.h>

#include "php_network.h"
#include "php_elasticache.h"

#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#endif

#ifdef PHP_WIN32
# include "win32/php_stdint.h"
#else
# ifndef HAVE_INT32_T
#  if SIZEOF_INT == 4
typedef int int32_t;
#  elif SIZEOF_LONG == 4
typedef long int int32_t;
#  endif
# endif

# ifndef HAVE_UINT32_T
#  if SIZEOF_INT == 4
typedef unsigned int uint32_t;
#  elif SIZEOF_LONG == 4
typedef unsigned long int uint32_t;
#  endif
# endif
#endif

#define EC_STRFREE(s) if(s) { free(s); }

ZEND_DECLARE_MODULE_GLOBALS(elasticache)

#ifdef COMPILE_DL_ELASTICACHE
ZEND_GET_MODULE(elasticache)
#endif

static PHP_INI_MH(OnUpdateEndpoints)
{
    elasticache_debug("%s - endpoints INI value updated", CFN);

    /* Parse the endpoints into a list of endpoint name -> host[:port] */
    elasticache_parse_endpoints(new_value TSRMLS_CC);

    return SUCCESS;
}

PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("elasticache.endpoints", "", PHP_INI_ALL, OnUpdateEndpoints, rawEndpoints, zend_elasticache_globals, elasticache_globals)
    STD_PHP_INI_ENTRY("elasticache.endpoint_refresh_interval", "1000", PHP_INI_ALL, OnUpdateLong, endpointRefreshInterval, zend_elasticache_globals, elasticache_globals)
    STD_PHP_INI_ENTRY("elasticache.endpoint_refresh_timeout", "250", PHP_INI_ALL, OnUpdateLong, endpointRefreshTimeout, zend_elasticache_globals, elasticache_globals)
PHP_INI_END()

static void elasticache_debug(const char *format, ...)
{
    TSRMLS_FETCH();

    char buffer[1024];
    va_list args;

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = '\0';
    php_printf("%s\n", buffer);
}

static void elasticache_init_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC)
{
    EC_G(endpoints) = NULL;
    EC_G(endpointCount) = 0;
    EC_G(endpointRefreshInterval) = 1000;
    EC_G(endpointRefreshTimeout) = 250;

    elasticache_debug("%s - globals initialized", CFN);
}

static void elasticache_destroy_globals(zend_elasticache_globals *elasticache_globals_p TSRMLS_DC)
{
}

static struct timeval _convert_ms_to_tv(long ms)
{
    struct timeval tv;
    int seconds;

    seconds = ms / 1000;
    tv.tv_sec = seconds;
    tv.tv_usec = ((ms - (seconds * 1000)) * 1000) % 1000000;

    return tv;
}

static int elasticache_should_refresh(TSRMLS_D)
{
    time_t secDiff;
    long nanoDiff, msDiff;
    struct timespec currentTime;

    /* Hard-coded to always update while testing. */
    return 1;

    /* This is our first check ever, which means we need to refresh. */
    if(EC_G(endpointLastRefresh).tv_sec == 0)
        return 1;

    clock_gettime(CLOCK_MONOTONIC, &currentTime);

    secDiff = currentTime.tv_sec - EC_G(endpointLastRefresh).tv_sec;
    nanoDiff = currentTime.tv_nsec - EC_G(endpointLastRefresh).tv_nsec;

    /* We need milliseconds here since the refresh interval is in milliseconds. */
    msDiff = ((secDiff * 1000) + (nanoDiff / 1000000.0)) + 0.5;

    return msDiff > EC_G(endpointRefreshInterval);
}

static void elasticache_clear_endpoints(TSRMLS_D)
{
    elasticache_endpoint **endpoints = EC_G(endpoints);
    int endpointCount = EC_G(endpointCount), i = 0;

    /* Clear out the old endpoints. */
    if(endpoints != NULL)
    {
        /* Free the individual endpoints. */
        for(i = 0; i < endpointCount; i++)
        {
            elasticache_debug("%s - freeing endpoint object", CFN);
            elasticache_free_endpoint(*(endpoints + i));
        }

        free(endpoints);

        EC_G(endpoints) = NULL;
    }

    EC_G(endpointCount) = 0;

    elasticache_debug("%s - done freeing endpoints", CFN);
}

static void elasticache_parse_endpoints(char *rawEndpoints TSRMLS_DC)
{
    elasticache_endpoint *endpoint = NULL;
    char *rawEndpoint = NULL;
    int endpointCount = 0;

    /* If we have no endpoints, we have nothing to parse. */
    if(!rawEndpoints || !strlen(rawEndpoints))
        return;

    /* Clear out the old endpoints. */
    elasticache_clear_endpoints(TSRMLS_C);

    /* Go through the list of endpoints, parsing each accordingly. */
    elasticache_debug("%s - starting to parse endpoints", CFN);

    rawEndpoint = strtok(rawEndpoints, ",");
    while(rawEndpoint)
    {
        /* Try to parse this as a URL, since our format is basically a URL. */
        endpoint = elasticache_parse_endpoint(rawEndpoint);
        if(!endpoint)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "failed to parse ElastiCache configuration endpoint: %s", rawEndpoint);
            continue;
        }

        /* We need a scheme and host at the bare minimum. */
        if(!endpoint->scheme || !endpoint->host)
        {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "missing endpoint name and/or endpoint host for ElastiCache: %s", rawEndpoint);
            continue;
        }

        /* Use the default Memcached port if none was specified. */
        if(!endpoint->port)
        {
            endpoint->port = 11211;
        }

        /* Store the endpoint object. */
        elasticache_debug("%s - found endpoint '%s' from list, adding", CFN, rawEndpoint);

        EC_G(endpoints) = realloc(EC_G(endpoints), (sizeof(elasticache_endpoint*) * ++endpointCount));
        *(EC_G(endpoints) + (endpointCount - 1)) = endpoint;

        /* Continue on. */
        elasticache_debug("%s - trying next match in list", CFN);
        rawEndpoint = strtok(NULL, ",");
    }

    EC_G(endpointCount) = endpointCount;

    /* Got em all! */
    elasticache_debug("%s - all done parsing endpoints", CFN);
}

static void elasticache_update(TSRMLS_D)
{
    elasticache_endpoint *endpoint = NULL;
    elasticache_endpoint **endpoints = NULL;
    char *endpointName = NULL, *errmsg = NULL;
    zval **existingElasticacheArr = NULL;
    zval *newElasticacheArr = NULL, *newEndpointsArr = NULL, *newEndpointArr = NULL;
    elasticache_cluster *cluster = NULL;
    int i, j;

    /* If it's not time to refresh, bail out. */
    if(!elasticache_should_refresh(TSRMLS_C))
    {
        elasticache_debug("%s - refresh attempted; not time yet", CFN);
        return;
    }

    /* If we have no endpoints, we definitely don't have anything to update. */
    if(!EC_G(endpointCount))
    {
        elasticache_debug("%s - refresh attempted, but no endpoints", CFN);
        return;
    }

    elasticache_debug("%s - attempting to refresh", CFN);

    /* Get our parent array to shove in $_SERVER. */
    MAKE_STD_ZVAL(newElasticacheArr);
    array_init(newElasticacheArr);

    endpoints = EC_G(endpoints);

    /* Iterate through all endpoints, getting the nodes constituting their cluster. */
    for(i = 0; i < EC_G(endpointCount); i++) {
        endpoint = (endpoints + i);

        /* Until we rewrite the URL parsing code to only handle what we care about, harmlessly
           alias 'scheme' to 'endpointName'. */
        endpointName = endpoint->scheme;

        elasticache_debug("%s - found endpoint '%s' while going down our list of endpoints", CFN, endpointName);

        /* Now contact the configuration node and see if they have anything for us. */
        cluster = elasticache_get_cluster(endpoint, errmsg TSRMLS_CC);
        if(cluster)
        {
            elasticache_debug("%s - got back %d node(s) for endpoint '%s'", CFN, cluster->nodeCount, endpointName);

            MAKE_STD_ZVAL(newEndpointsArr);
            array_init(newEndpointsArr);

            /* For each node, create a separate array entry. */
            for(j = 0; j < cluster->nodeCount; j++)
            {
                endpoint = *(cluster->nodes + j);

                MAKE_STD_ZVAL(newEndpointArr);
                array_init(newEndpointArr);

                add_next_index_string(newEndpointArr, endpoint->host, 1);
                add_next_index_long(newEndpointArr, endpoint->port);

                add_next_index_zval(newEndpointsArr, newEndpointArr);
            }

            /* Add our endpoint nodes to their parent container. */
            add_assoc_zval(newElasticacheArr, endpointName, newEndpointsArr);
        } else if(errmsg) {
            elasticache_debug("%s - got error message from elasticache_grab_configuration on endpoint '%s': %s", CFN, endpointName, errmsg);
            efree(errmsg);
        }
    }

    /* Now set the $_SERVER global with our parent array. */
    if(zend_hash_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER"), (void**)&existingElasticacheArr) == SUCCESS)
    {
        zend_hash_update(Z_ARRVAL_PP(existingElasticacheArr), "ELASTICACHE", sizeof("ELASTICACHE"), &newElasticacheArr, sizeof(zval*), NULL);
    }

    /* Mark our last refresh time as now. */
    clock_gettime(CLOCK_MONOTONIC, &EC_G(endpointLastRefresh));
}

static elasticache_cluster* elasticache_get_cluster(elasticache_endpoint *endpoint, char *errmsg TSRMLS_DC)
{
    php_stream *stream = NULL;
    struct timeval tv;
    char buf[8192];
    char *hostname = NULL, *hash_key = NULL, *errmsg2 = NULL, *response = NULL;
    int responseLen, hostnameLen, errcode, result, nodeCount;
    elasticache_cluster *cluster = NULL;

    /* Set timeout for the connection. */
    tv.tv_sec = 0;
    tv.tv_usec = EC_G(endpointRefreshTimeout) * 1000;

    /* Build our hostname. */
    hostnameLen = spprintf(&hostname, 0, "%s:%d", endpoint->host, endpoint->port);

    /* Get our stream and connect to the endpoint. */
    stream = php_stream_xport_create(hostname, hostnameLen,
                                     ENFORCE_SAFE_MODE | REPORT_ERRORS,
                                     STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT,
                                     hash_key, &tv, NULL, &errmsg2, &errcode);

    efree(hostname);

    /* Make sure we got our stream successfully. */
    if(!stream)
    {
        if(errmsg)
        {
            spprintf(&errmsg, 0, "can't connect to ElastiCache configuration '%s': %s", endpoint->host, errmsg2);
        }
        efree(errmsg2);

        return NULL;
    }

    /* Set some options on our stream. */
    php_stream_auto_cleanup(stream);
    php_stream_set_option(stream, PHP_STREAM_OPTION_WRITE_BUFFER, PHP_STREAM_BUFFER_NONE, NULL);

    /* Send the command to get the cluster configuration. */
    if(elasticache_sendcmd(stream, "config get cluster" TSRMLS_CC) < 0)
    {
        if(errmsg)
        {
            spprintf(&errmsg, 0, "failed to send cluster config command to '%s'", endpoint->host);
        }
        return NULL;
    }

    /* Get the result back. */
    if((result = elasticache_read_value(stream, &buf[0], sizeof(buf), &response, &responseLen TSRMLS_CC)) < 0)
    {
        if(errmsg)
        {
            spprintf(&errmsg, 0, "failed to get response from '%s'", endpoint->host);
        }
        return NULL;
    }

    if(!result) {
        /* We couldn't find the value.  wtf m8? */
        if(errmsg)
        {
            spprintf(&errmsg, 0, "failed to read value from configuration node response '%s'", endpoint->host);
        }
        return NULL;
    }

    /* We now have our response, so now parse it. */
    nodeCount = elasticache_parse_config(response, responseLen, &cluster);
    if(!nodeCount) {
        /* No nodes... that ain't right.  Bail out, yo! */
        if(errmsg)
        {
            spprintf(&errmsg, 0, "parsed zero cache nodes out of configuration endpoint response '%s'", endpoint->host);
        }
        return NULL;
    }

    /* Close our stream since we're all done. */
    php_stream_close(stream);
    stream = NULL;

    return cluster;
}

static int elasticache_parse_config(char *response, int responseLen, elasticache_cluster **cluster)
{
    char *nodePos = NULL, *node = NULL, *currentNode = NULL, *nodeFqdn = NULL, *tmp = NULL, *nodeFull = NULL;
    char **nodes = NULL;
    elasticache_endpoint *endpoint = NULL;
    int i, len, nodePort, nodeCount;

    /* find where the config version line ends */
    nodePos = strstr(response, "\n");
    if(!nodePos)
    {
        return 0;
    }

    /* Break apart the response into just the nodes it contains. */
    nodePos = strtok((nodePos + 1), " \n");
    while(nodePos)
    {
        len = strlen(nodePos);
        node = emalloc(len + 1);
        strcpy(node, nodePos);

        nodeCount++;

        nodes = erealloc(nodes, sizeof(char*) * nodeCount);

        *(nodes + (nodeCount - 1)) = node;

        nodePos = strtok(NULL, " \r\n");
    }

    /* If we actually got some, create our cluster object. Allocate enough space for all the nodes
       we think we'll get, but get the node count by waiting until we parse each node entry
       successfully before incrementing. */
    *cluster = malloc(sizeof(elasticache_cluster*));
    (*cluster)->nodes = malloc(sizeof(elasticache_endpoint*) * nodeCount);
    (*cluster)->nodeCount = 0;

    /* Loop through each node and break it down, adding it to our cluster object. */
    for(i = 0; i < nodeCount; i++)
    {
        currentNode = *(nodes + i);

        /* This should be our node FQDN. */
        nodePos = strtok(currentNode, "|");
        if(nodePos)
        {
            len = strlen(nodePos);
            nodeFqdn = emalloc(len + 1);
            strcpy(nodeFqdn, nodePos);
        }

        /* This should normally be the private IP but it might be the port since strtok should,
           I believe, skip over empty values.  We'll just have to find out! :D */
        nodePos = strtok(NULL, "|");
        if(nodePos)
        {
            len = strlen(nodePos);
            tmp = emalloc(len + 1);
            strcpy(tmp, nodePos);
        }

        /* Try for the port now and see what happens. */
        nodePos = strtok(NULL, "|");
        if(nodePos)
        {
            /* If we got the private IP: free it because we're not going to use it after all. */
            if(tmp)
            {
                efree(tmp);
            }

            nodePort = atoi(nodePos);

        }
        else if(tmp)
        {
            nodePort = atoi(tmp);
        }

        if(!nodeFqdn || !nodePort)
        {
            /* What do we do here? Backing out is ugly because of memory clean-up, I feel like,
               but continuing on doesn't really make sense. :( */
            if(nodeFqdn)
            {
                efree(nodeFqdn);
            }

            if(tmp)
            {
                efree(tmp);
            }

            continue;
        }

        /* Create our endpoint object. */
        endpoint = calloc(1, sizeof(elasticache_endpoint));
        endpoint->host = strdup(nodeFqdn);
        endpoint->port = nodePort;

        /* Store the endpoint. */
        *((*cluster)->nodes + i) = endpoint;
        (*cluster)->nodeCount++;

        /* Free our temporary holders. */
        efree(nodeFqdn);
        if(tmp)
        {
            efree(tmp);
        }
    }

    /* Clean up old entries. */
    for (i = 0; i < nodeCount; i++) {
        char *currentNode = *(nodes + i);
        efree(currentNode);
    }

    efree(nodes);

    return (*cluster)->nodeCount;
}

static int elasticache_sendcmd(php_stream *stream, char *cmd TSRMLS_DC)
{
    char *command = NULL;
    int commandLen, cmdlen;

    if (!stream || !cmd)
    {
        return -1;
    }

    cmdlen = strlen(cmd);

    command = emalloc(cmdlen + sizeof("\r\n"));
    memcpy(command, cmd, cmdlen);
    memcpy(command + cmdlen, "\r\n", sizeof("\r\n") - 1);
    commandLen = cmdlen + sizeof("\r\n") - 1;
    command[commandLen] = '\0';

    /* todo: handle timeouts */

    if (php_stream_write(stream, command, commandLen) != commandLen) {
        /* todo: set error data that writing command failed */
        efree(command);
        return -1;
    }

    efree(command);

    return 1;
}

static int elasticache_read_value(php_stream *stream, char *buf, int bufLen, char **value, int *valueLen TSRMLS_DC)
{
    char *data = NULL;
    int responseLen, dataLen, i, size, flags;

    /* read "VALUE <key> <flags> <bytes>\r\n" header line */
    if ((responseLen = elasticache_readline(stream, buf, bufLen TSRMLS_CC)) < 0)
    {
        /* todo: send back up error message that we couldn't parse server's response */
        return -1;
    }

    /* reached the end of the data */
    if (elasticache_str_left(buf, "END", responseLen, sizeof("END") - 1))
    {
        return 0;
    }

    if (elasticache_parse_response(buf, responseLen, NULL, NULL, &flags, &dataLen) < 0)
    {
        return -1;
    }

    /* data_len + \r\n + \0 */
    data = emalloc(dataLen + 3);

    for (i = 0; i < dataLen + 2; i += size) {
        if ((size = php_stream_read(stream, data + i, dataLen + 2 - i)) == 0)
        {
            // todo: push error up about failing to read the response body
            efree(data);
            return -1;
        }
    }

    data[dataLen] = '\0';

    /* todo: potentially handle decompression */

    *value = data;
    *valueLen = dataLen;

    return 1;
}

static int elasticache_readline(php_stream *stream, char *buf, int bufLen TSRMLS_DC)
{
    char *response = NULL;
    size_t responseLen;

    if(!stream)
    {
        /* todo: send back error that stream is closed */
        return -1;
    }

    response = php_stream_get_line(stream, buf, bufLen, &responseLen);
    if(response)
    {
        return responseLen;
    }

    /* todo: send back an error string here or something */
    return -1;
}

static int elasticache_parse_response(char *response, int responseLen, char **key, int *keyLen, int *flags, int *valueLen)
{
    int i, n = 0;
    int spaces[3];

    if(!response || responseLen <= 0)
    {
        /* todo: send back error about empty response */
        return -1;
    }

    for(i=0, n=0; i < responseLen && n < 3; i++)
    {
        if (response[i] == ' ')
        {
            spaces[n++] = i;
        }
    }

    if(n < 3)
    {
        /* todo: send back error about malformed VALUE header */
        return -1;
    }

    if(key)
    {
        int len = spaces[1] - spaces[0] - 1;

        *key = emalloc(len + 1);
        *keyLen = len;

        memcpy(*key, response + spaces[0] + 1, len);
        (*key)[len] = '\0';
    }

    *flags = atoi(response + spaces[1]);
    *valueLen = atoi(response + spaces[2]);

    if(*flags < 0 || *valueLen < 0)
    {
        /* todo: send back error about malformed VALUE header */
        return -1;
    }

    return 1;
}

static int elasticache_str_left(char *haystack, char *needle, int haystackLen, int needleLen)
{
    char *found = php_memnstr(haystack, needle, needleLen, haystack + haystackLen);
    if((found - haystack) == 0)
    {
        return 1;
    }

    return 0;
}

static void elasticache_free_endpoint(elasticache_endpoint *endpoint)
{
    EC_STRFREE(endpoint->scheme)
    EC_STRFREE(endpoint->user)
    EC_STRFREE(endpoint->pass)
    EC_STRFREE(endpoint->host)
    EC_STRFREE(endpoint->path)
    EC_STRFREE(endpoint->query)
    EC_STRFREE(endpoint->fragment)

    free(endpoint);
}

static char *elasticache_replace_controlchars(char *str, int len)
{
    unsigned char *s = (unsigned char *)str;
    unsigned char *e = (unsigned char *)str + len;

    if(!str)
    {
        return NULL;
    }

    while(s < e)
    {
        if(iscntrl(*s))
        {
            *s = '_';
        }

        s++;
    }

    return str;
}

static elasticache_endpoint *elasticache_parse_endpoint(char *str)
{
    char port_buf[6];
    elasticache_endpoint *ret = calloc(1, sizeof(elasticache_endpoint));
    const char *s, *e, *p, *pp, *ue;
    int length = strlen(str);

    s = str;
    ue = s + length;

    /* parse scheme */
    if((e = memchr(s, ':', length)) && (e - s))
    {
        /* validate scheme */
        p = s;
        while (p < e)
        {
            /* scheme = 1*[ lowalpha | digit | "+" | "-" | "." ] */
            if(!isalpha(*p) && !isdigit(*p) && *p != '+' && *p != '.' && *p != '-')
            {
                if (e + 1 < ue)
                {
                    goto parse_port;
                }
                else
                {
                    goto just_path;
                }
            }

            p++;
        }

        if(*(e + 1) == '\0')
        {
            /* only scheme is available */
            ret->scheme = strndup(s, (e - s));
            elasticache_replace_controlchars(ret->scheme, (e - s));
            goto end;
        }

        /* certain schemas like mailto: and zlib: may not have any / after them this check ensures we support those. */
        if(*(e+1) != '/')
        {
            /* check if the data we get is a port this allows us to correctly parse things like a.com:80 */
            p = e + 1;
            while(isdigit(*p))
            {
                p++;
            }

            if((*p == '\0' || *p == '/') && (p - e) < 7)
            {
                goto parse_port;
            }

            ret->scheme = strndup(s, (e-s));
            elasticache_replace_controlchars(ret->scheme, (e - s));

            length -= ++e - s;
            s = e;
            goto just_path;
        }
        else
        {
            ret->scheme = strndup(s, (e-s));
            elasticache_replace_controlchars(ret->scheme, (e - s));

            if(*(e+2) == '/')
            {
                s = e + 3;

                if(!strncasecmp("file", ret->scheme, sizeof("file")))
                {
                    if(*(e + 3) == '/')
                    {
                        goto nohost;
                    }
                }
            }
            else
            {
                if(!strncasecmp("file", ret->scheme, sizeof("file")))
                {
                    s = e + 1;
                    goto nohost;
                }
                else
                {
                    length -= ++e - s;
                    s = e;
                    goto just_path;
                 }
            }
        }
    }
    else if(e)
    {
        /* no scheme, look for port */
parse_port:
        p = e + 1;
        pp = p;

        while(pp-p < 6 && isdigit(*pp))
        {
            pp++;
        }

        if(pp-p < 6 && (*pp == '/' || *pp == '\0'))
        {
            memcpy(port_buf, p, (pp-p));
            port_buf[pp-p] = '\0';
            ret->port = atoi(port_buf);
        }
        else
        {
            goto just_path;
        }
    }
    else
    {
just_path:
        ue = s + length;
        goto nohost;
    }

    e = ue;

    if(!(p = memchr(s, '/', (ue - s))))
    {
        if((p = memchr(s, '?', (ue - s))))
        {
            e = p;
        }
        else if((p = memchr(s, '#', (ue - s))))
        {
            e = p;
        }
    }
    else
    {
        e = p;
    }

    /* check for login and password */
    if((p = memchr(s, '@', (e-s))))
    {
        if((pp = memchr(s, ':', (p-s))))
        {
            if((pp-s) > 0)
            {
                ret->user = strndup(s, (pp-s));
                elasticache_replace_controlchars(ret->user, (pp - s));
            }

            pp++;

            if(p-pp > 0)
            {
                ret->pass = strndup(pp, (p-pp));
                elasticache_replace_controlchars(ret->pass, (p-pp));
            }
        }
        else
        {
            ret->user = strndup(s, (p-s));
            elasticache_replace_controlchars(ret->user, (p-s));
        }

        s = p + 1;
    }

    /* check for port */
    if(*s == '[' && *(e-1) == ']')
    {
        /* short circuit portscan; we're dealing with an IPv6 embedded address */
        p = s;
    }
    else
    {
        /* memchr is a GNU specific extension; emulate for wide compatability */
        for(p = e; *p != ':' && p >= s; p--);
    }

    if(p >= s && *p == ':')
    {
        if(!ret->port)
        {
            p++;

            if(e-p > 5) /* port cannot be longer then 5 characters */
            {
                EC_STRFREE(ret->scheme);
                EC_STRFREE(ret->user);
                EC_STRFREE(ret->pass);
                free(ret);
                return NULL;
            }
            else if(e - p > 0)
            {
                memcpy(port_buf, p, (e-p));
                port_buf[e-p] = '\0';
                ret->port = atoi(port_buf);
            }

            p--;
        }
    }
    else
    {
        p = e;
    }

    /* check if we have a valid host, if we don't reject the string as url */
    if((p-s) < 1)
    {
        EC_STRFREE(ret->scheme);
        EC_STRFREE(ret->user);
        EC_STRFREE(ret->pass);
        free(ret);
        return NULL;
    }

    ret->host = strndup(s, (p-s));
    elasticache_replace_controlchars(ret->host, (p - s));

    if(e == ue)
    {
        return ret;
    }

    s = e;

nohost:
    if((p = memchr(s, '?', (ue - s))))
    {
        pp = strchr(s, '#');

        if(pp && pp < p)
        {
            p = pp;
            pp = strchr(pp+2, '#');
        }

        if(p - s)
        {
            ret->path = strndup(s, (p-s));
            elasticache_replace_controlchars(ret->path, (p - s));
        }

        if(pp)
        {
            if(pp - ++p)
            {
                ret->query = strndup(p, (pp-p));
                elasticache_replace_controlchars(ret->query, (pp - p));
            }

            p = pp;
            goto label_parse;
        }
        else if(++p - ue)
        {
            ret->query = strndup(p, (ue-p));
            elasticache_replace_controlchars(ret->query, (ue - p));
        }
    }
    else if((p = memchr(s, '#', (ue - s))))
    {
        if(p - s)
        {
            ret->path = strndup(s, (p-s));
            elasticache_replace_controlchars(ret->path, (p - s));
        }
label_parse:
        p++;

        if(ue - p)
        {
            ret->fragment = strndup(p, (ue-p));
            elasticache_replace_controlchars(ret->fragment, (ue - p));
        }
    }
    else
    {
        ret->path = strndup(s, (ue-s));
        elasticache_replace_controlchars(ret->path, (ue - s));
    }
end:
    return ret;
}

PHP_FUNCTION(elasticache_version)
{
    if(zend_parse_parameters_none() == FAILURE)
    {
        return;
    }

    RETURN_STRING(PHP_ELASTICACHE_EXTVER, 1);
}

PHP_RINIT_FUNCTION(elasticache)
{
    elasticache_update(TSRMLS_C);

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(elasticache)
{
    return SUCCESS;
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

zend_function_entry elasticache_functions[] = {
    PHP_FE(elasticache_version, elasticache_version_args)
    {NULL, NULL, NULL}
};

static const zend_module_dep elasticache_deps[] = {
    {NULL, NULL, NULL}
};

zend_module_entry elasticache_module_entry = {
#if ZEND_MODULE_API_NO >= 20050922
    STANDARD_MODULE_HEADER_EX, NULL,
    (zend_module_dep*)elasticache_deps,
#else
    STANDARD_MODULE_HEADER,
#endif
    "elasticache",
    elasticache_functions,
    PHP_MINIT(elasticache),
    PHP_MSHUTDOWN(elasticache),
    PHP_RINIT(elasticache),
    PHP_RSHUTDOWN(elasticache),
    PHP_MINFO(elasticache),
    PHP_ELASTICACHE_EXTVER,
    STANDARD_MODULE_PROPERTIES
};
