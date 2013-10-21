PHP_ARG_ENABLE(elasticache, whether to enable elasticache,
[  --enable-elasticache               Enable elasticache])

if test "$PHP_ELASTICACHE" != "no"; then
  #
  # Add libraries and other stuff here (below is how you would add libexample):
  #  
  #  PHP_ADD_LIBRARY_WITH_PATH(example, $PHP_LIBEXAMPLE_DIR/$PHP_LIBDIR, ELASTICACHE_SHARED_LIBADD)
  #  PHP_ADD_INCLUDE($PHP_LIBEXAMPLE_INCDIR)
  #  PHP_SUBST(ELASTICACHE_SHARED_LIBADD)
  #
  #  $PHP_LIBEXAMPLE_DIR and $PHP_LIBEXAMPLE_INCDIR need to be resolved somehow, for example pkg-config
  #

  PHP_NEW_EXTENSION(elasticache, elasticache.c, $ext_shared)
fi

