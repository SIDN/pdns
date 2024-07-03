dnl XXX clean this up later

AC_DEFUN([PDNS_WITH_SQISIGN], [
  AC_MSG_CHECKING([whether we will be linking in sqisign])
  AC_ARG_WITH([sqisign],
    AS_HELP_STRING([--with-sqisign],[use sqisign @<:@default=auto@:>@]),
    [with_sqisign=$withval],
    [with_sqisign=auto],
  )
  AC_MSG_RESULT([$with_sqisign])

  AS_IF([test "x$with_sqisign" != "xno"], [
    AS_IF([test "x$with_sqisign" = "xyes" -o "x$with_sqisign" = "xauto"], [
       AC_DEFINE([HAVE_SQISIGN], [1], [Define if using SQISign.])
       LIBS="$LIBS -lsqisign_lvl1 -lsqisign_protocols_lvl1 -lsqisign_id2iso_lvl1 -lsqisign_klpt_lvl1 -lsqisign_precomp_lvl1 -lsqisign_quaternion_generic -lsqisign_intbig_generic -lsqisign_gf_lvl1 -lsqisign_ec_lvl1 -lsqisign_common_sys -lgmp"
       SQISIGN_LIBS="$LIBS"
    ])
  ])
  AM_CONDITIONAL([LIBSQISIGN], [test "x$SQISIGN_LIBS" != "x"])
  AS_IF([test "x$with_sqisign" = "xyes"], [
    AS_IF([test x"$SQISIGN_LIBS" = "x"], [
      AC_MSG_ERROR([sqisign requested but libraries were not found])
    ])
  ])
])
