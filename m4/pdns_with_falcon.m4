dnl XXX clean this up later

AC_DEFUN([PDNS_WITH_FALCON], [
  AC_MSG_CHECKING([whether we will be linking in falcon])
  AC_ARG_WITH([falcon],
    AS_HELP_STRING([--with-falcon],[use falcon @<:@default=auto@:>@]),
    [with_falcon=$withval],
    [with_falcon=auto],
  )
  AC_MSG_RESULT([$with_falcon])

  AS_IF([test "x$with_falcon" != "xno"], [
    AS_IF([test "x$with_falcon" = "xyes" -o "x$with_falcon" = "xauto"], [
       AC_DEFINE([HAVE_FALCON], [1], [Define if using FALCON.])
       LIBS="$LIBS -lfalcon-512_clean"
       FALCON_LIBS="$LIBS"
    ])
  ])
  AM_CONDITIONAL([LIBFALCON], [test "x$FALCON_LIBS" != "x"])
  AS_IF([test "x$with_falcon" = "xyes"], [
    AS_IF([test x"$FALCON_LIBS" = "x"], [
      AC_MSG_ERROR([falcon requested but libraries were not found])
    ])
  ])
])
