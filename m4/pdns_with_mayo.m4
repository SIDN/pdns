dnl XXX clean this up later

AC_DEFUN([PDNS_WITH_MAYO], [
  AC_MSG_CHECKING([whether we will be linking in mayo])
  AC_ARG_WITH([mayo],
    AS_HELP_STRING([--with-mayo],[use mayo @<:@default=auto@:>@]),
    [with_mayo=$withval],
    [with_mayo=auto],
  )
  AC_MSG_RESULT([$with_mayo])

  AS_IF([test "x$with_mayo" != "xno"], [
    AS_IF([test "x$with_mayo" = "xyes" -o "x$with_mayo" = "xauto"], [
       AC_DEFINE([HAVE_MAYO], [1], [Define if using MAYO.])
       LIBS="$LIBS -lmayo_2 -lmayo_common_sys"
       MAYO_LIBS="$LIBS"
    ])
  ])
  AM_CONDITIONAL([LIBMAYO], [test "x$MAYO_LIBS" != "x"])
  AS_IF([test "x$with_mayo" = "xyes"], [
    AS_IF([test x"$MAYO_LIBS" = "x"], [
      AC_MSG_ERROR([mayo requested but libraries were not found])
    ])
  ])
])
