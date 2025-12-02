dnl configure.in
dnl
dnl Copyright (c) 2000 Dug Song <dugsong@monkey.org>
dnl
dnl $Id: configure.in,v 1.27 2000/12/20 16:31:21 dugsong Exp $

AC_INIT
AC_CONFIG_SRCDIR([dsniff.c])

AC_CONFIG_HEADERS([config.h])

dnl Initialize prefix.
if test "$prefix" = "NONE"; then
   prefix="/usr/local"
fi

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl Checks for header files.
AC_PATH_XTRA

AC_CHECK_HEADERS(err.h fcntl.h sys/ioctl.h sys/queue.h unistd.h libgen.h net/if_tun.h)
dnl XXX - Solaris sux.

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM
dnl XXX - Solaris sux.
AC_CHECK_TYPE(u_int32_t, uint32_t)
AC_CHECK_TYPE(u_int64_t, uint64_t)
dnl XXX - Linux sux.
AC_CHECK_TYPE(in_addr_t, u_int32_t)
CFLAGS="$CFLAGS -D_DEFAULT_SOURCE"

dnl Checks for library functions.
AC_PROG_CC
AC_FUNC_MEMCMP

AC_FUNC_STRFTIME
AC_CHECK_FUNCS(gethostname socket strdup strstr)
AC_CHECK_LIB(rpcsvc, xdr_fhstatus)
AC_CHECK_LIB([tirpc], [clnt_tli_create], [X_TIRPC_LIB="-ltirpc"])
AC_SUBST(X_TIRPC_LIB)
AC_CHECK_LIB([ibverbs], [ibv_close_device], [X_IBVERBS_LIB="-libverbs"])
AC_SUBST(X_IBVERBS_LIB)
dnl XXX - Solaris sux.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyname)
dnl XXX - feh, everything except OpenBSD sux.
AC_CHECK_LIB(resolv, dn_expand)
AC_CHECK_LIB(resolv, __dn_expand)
dnl We cant tell if the static libnids.a is build with glib2. Better add
dnl it just in case.
AC_CHECK_LIB(glib-2.0, g_mutex_init)
AC_CHECK_LIB(gthread-2.0, g_thread_init)

AC_REPLACE_FUNCS(dirname strlcpy strlcat strsep)
needmd5=no
AC_CHECK_FUNCS(MD5Update, , [needmd5=yes])
if test $needmd5 = yes; then
   LIBOBJS="$LIBOBJS md5.o"
fi
neederr=no
AC_CHECK_FUNCS(warnx, , [neederr=yes])
if test $neederr = yes; then
   LIBOBJS="$LIBOBJS err.o"
fi
needethers=no
AC_CHECK_FUNCS(ether_ntoa, , [needethers=yes])
if test $needethers = yes; then
   LIBOBJS="$LIBOBJS ethers.o"
fi

dnl Checks for BSD tunnel device
dnl if test "x$ac_cv_header_net_if_tun_h" = "xyes"; then
dnl   TCPHIJACK="tcphijack"
dnl fi
AC_SUBST(TCPHIJACK)

dnl Checks for X11
if test "x$no_x" = "x"; then
   WEBSPY="webspy"; AC_SUBST(WEBSPY)
fi

AC_MSG_CHECKING([whether to enable static build])
AC_ARG_ENABLE([static],
	        [AS_HELP_STRING([--enable-static],[Compile static binary])],
		[], [enable_static="no"])
AC_MSG_RESULT([$enable_static])

if test "x$enable_static" = "xyes"; then
   LDFLAGS_STATIC="-static"
   dnl -static requires to satisfy forward-dependencies
   AC_CHECK_LIB([intl], [libintl_gettext])
fi

AC_MSG_CHECKING([whether to enable BerkelyDB])
AC_ARG_ENABLE([berkeleydb],
   [AS_HELP_STRING([--enable-berkeleydb],[Build with BerkeleyDB])],
   [BDB="yes"], [BDB="no"])
AC_MSG_RESULT([$BDB])
if test x"${BDB}" = "xyes"; then
   AC_DEFINE([WITH_BERKELEYDB], [1], [BLah])
fi


if test x"${BDB}" = xyes; then
dnl Checks for Berkeley DB
AC_MSG_CHECKING(for Berkeley DB with 1.85 compatibility)
AC_ARG_WITH(db,
[  --with-db=DIR           use Berkeley DB (with --enable-compat185) in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/build_unix/db_185.h -a \
	     -f $withval/build_unix/libdb.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	AC_DEFINE(HAVE_DB_185_H)
	DBINC="-I$withval/build_unix"
	DBLIB="-L$withval/build_unix -ldb"
     elif test -f $withval/dist/db_185.h -a \
	       -f $withval/dist/libdb.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	AC_DEFINE(HAVE_DB_185_H)
	DBINC="-I$withval/dist"
	DBLIB="-L$withval/dist -ldb"
     elif test -f $withval/include/db_185.h -a \
	       -f $withval/lib/libdb.a; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	AC_DEFINE(HAVE_DB_185_H)
	DBINC="-I$withval/include"
	DBLIB="-L$withval/lib -ldb"
     else
        AC_MSG_ERROR(db_185.h or libdb.a not found in $withval or not configured with --enable-compat185)
     fi
     ;;
  esac ],
[ for dir in ${prefix}/BerkeleyDB.3.1 ${prefix}/BerkeleyDB.3.0 \
	     ${prefix}/BerkeleyDB ${prefix}/db ${prefix}; do
    if test -f ${dir}/include/db_185.h; then
       AC_DEFINE(HAVE_DB_185_H)
       DBINC="-I${dir}/include"
       DBLIB="-L${dir}/lib -ldb"
       have_db=yes
       break
    elif test -f ${dir}/include/db.h; then
       AC_DEFINE(HAVE_DB_H)
       DBINC="-I${dir}/include"
       DBLIB="-L${dir}/lib -ldb"
       have_db=yes
       break
    fi
  done
  if test "x$have_db" = "x"; then
     if test -f /usr/include/db2/db_185.h; then
	AC_DEFINE(HAVE_DB_185_H)
	DBINC="-I/usr/include/db2"
	DBLIB="-ldb2"
	have_db=yes
     elif test -f /usr/include/db_185.h; then
        AC_DEFINE(HAVE_DB_185_H)
        DBLIB="-ldb"
        have_db=yes
     elif test -f /usr/include/db.h; then
        AC_DEFINE(HAVE_DB_H)
        have_db=yes
     fi
  fi
  if test "x$have_db" = "x"; then
        AC_MSG_ERROR(Berkeley DB with 1.85 compatibility not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(DBINC)
AC_SUBST(DBLIB)
fi
AC_SUBST(LDFLAGS_STATIC)

dnl Checks for libpcap
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[  --with-libpcap=DIR      use libpcap in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a -f $withval/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval -I$withval/bpf"
	PCAPLIB="-L$withval -lpcap"
     elif test -f $withval/include/pcap.h -a \
	       -f $withval/lib/libpcap.a; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval/include"
	PCAPLIB="-L$withval/lib -lpcap"
     else
        AC_MSG_ERROR(pcap.h,net/bpf.h,or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     PCAPLIB="-L${prefix}/lib -lpcap"
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  else
     AC_MSG_RESULT(no)
     AC_MSG_ERROR(libpcap not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)

dnl Checks for libnet
AC_MSG_CHECKING(for libnet)
AC_ARG_WITH(libnet,
[  --with-libnet=DIR       use libnet in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/include/libnet.h -a -f $withval/lib/libnet.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	if test -f $withval/bin/libnet-config; then
	   CFLAGS="$CFLAGS `$withval/bin/libnet-config --defines`"
	elif test -f $withval/libnet-config; then
	   CFLAGS="$CFLAGS `$withval/libnet-config --defines`"
	else
	   CFLAGS="$CFLAGS `libnet-config --defines`"
	fi
	LNETINC="-I$withval/include"
	LNETLIB="-L$withval/lib -lnet"
     else
        AC_MSG_ERROR(libnet.h or libnet.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/libnet.h; then
     CFLAGS="$CFLAGS `${prefix}/bin/libnet-config --defines`"
     LNETINC="-I${prefix}/include"
     LNETLIB="-L${prefix}/lib -lnet"
  elif test -f /usr/include/libnet.h; then
     CFLAGS="$CFLAGS `libnet-config --defines`"
     LNETLIB="-lnet"
  else
     AC_MSG_RESULT(no)
     AC_MSG_ERROR(libnet not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(LNETINC)
AC_SUBST(LNETLIB)

dnl Checks for libnids
AC_MSG_CHECKING(for libnids)
AC_ARG_WITH(libnids,
[  --with-libnids=DIR      use libnids in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/src/nids.h -a -f $withval/src/libnids.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	NIDSINC="-I$withval/src"
	NIDSLIB="-L$withval/src -lnids"
     elif test -f $withval/include/nids.h -a -f $withval/lib/libnids.a; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	NIDSINC="-I$withval/include"
	NIDSLIB="-L$withval/lib -lnids"
     else
        AC_MSG_ERROR(nids.h or libnids.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/nids.h; then
     NIDSINC="-I${prefix}/include"
     NIDSLIB="-L${prefix}/lib -lnids"
  elif test -f /usr/include/nids.h; then
     NIDSLIB="-lnids"
  else
     AC_MSG_RESULT(no)
     AC_MSG_ERROR(libnids not found)
  fi
  AC_MSG_RESULT(yes) ]
)
save_cppflags="$CPPFLAGS"
CPPFLAGS="$NIDSINC"
AC_MSG_CHECKING(whether libnids version is good)
AC_EGREP_HEADER(pcap_filter, nids.h, AC_MSG_RESULT(yes), 
   [ AC_MSG_RESULT(no); AC_MSG_ERROR(libnids version 1.13 or greater required) ])
CPPFLAGS="$save_cppflags"
AC_SUBST(NIDSINC)
AC_SUBST(NIDSLIB)

dnl Checks for OpenSSL
AC_ARG_WITH(openssl, [  --with-openssl=DIR or yes      use OpenSSL in DIR, or detect with pkg-config], [], [with_openssl=yes])

case "x$with_openssl" in
  xyes)
     PKG_CHECK_MODULES([OPENSSL], [libssl libcrypto], [SSLINC="$OPENSSL_CFLAGS"; SSLLIB="$OPENSSL_LIBS"; WEBMITM="webmitm"])
     ;;
  x|xno)
     AC_MSG_CHECKING(for OpenSSL)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_CHECKING(for OpenSSL)
     if test -f $with_openssl/include/openssl/ssl.h -a -f $withval/libssl.a; then
        owd=`pwd`
        if cd $with_openssl; then withval=`pwd`; cd $owd; fi
	SSLINC="-I$with_openssl/include"
	SSLLIB="-L$with_openssl -lssl -lcrypto"
     elif test -f $with_openssl/include/openssl/ssl.h -a \
	       -f $with_openssl/lib/libssl.a; then
	owd=`pwd`
	if cd $with_openssl; then withval=`pwd`; cd $owd; fi
	SSLINC="-I$with_openssl/include"
	SSLLIB="-L$with_openssl/lib -lssl -lcrypto"
     else
        AC_MSG_ERROR(ssl.h or libssl.a not found in $with_openssl)
     fi
     AC_MSG_RESULT($with_openssl)
     WEBMITM="webmitm"
     ;;
esac

AC_SUBST(SSLINC)
AC_SUBST(SSLLIB)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
