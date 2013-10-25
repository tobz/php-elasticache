PHP_ARG_ENABLE(elasticache, whether to enable elasticache,
[  --enable-elasticache               Enable elasticache])

if test "$PHP_ELASTICACHE" != "no"; then
  PHP_CHECK_LIBRARY(rt,clock_gettime,
  [
    PHP_ADD_LIBRARY_WITH_PATH(rt, $ELASTICACHE_DIR/lib, ELASTICACHE_SHARED_LIBADD)
    AC_DEFINE(HAVE_ELASTICACHELIB,1,[ ])
  ],[
    AC_MSG_ERROR([wrong librt version or librt not found])
  ],[
    -L$ELASTICACHE_DIR/lib -lrt
  ])

  PHP_NEW_EXTENSION(elasticache, elasticache.c, $ext_shared)
fi

