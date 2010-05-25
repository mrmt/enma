#!/bin/sh
# $Id: build_all.sh 491 2008-08-26 06:14:49Z tsuruda $
# build and install

# command path
SED_CMD="sed"
GROUPS_CMD="groups"
TAR_CMD="tar"
if [ -x "`which gmake`" ]; then
    MAKE_CMD="gmake"
else
    MAKE_CMD="make"
fi

# processor switch
M64_FLAG=0

# build user/group
BUILD_USER=""
BUILD_GROUP=""

PREFIX="/usr/local"

# temporary varibale
THIS_FILE_NAME=$0
WORK=""
CURRENT_DIR=""
MILTER_CONFIG=""
CONFIGURE_OPTION=""
MAKE_DRY_RUN_OPTION=""


usage() {
    echo "[USAGE]:"
    echo "    ${THIS_FILE_NAME} [--prefix=PREFIX] [build]"
    echo "    ${THIS_FILE_NAME} [-n] install"
    echo "    ${THIS_FILE_NAME} clean"
    exit 1
}

abort() {
    echo ">>> [ERROR]: $1"
    exit 1
}

cd_build_dir() {
    local_exec_script_current_dir=`pwd`
    local_build_dir=`dirname ${THIS_FILE_NAME}`

    cd ${local_exec_script_current_dir}/${local_build_dir}
    WORK=`pwd`/work
}

set_user_name() {
    if [ "x" = "x${BUILD_USER}" ]; then
        BUILD_USER=${USER}
    fi
}

get_first_arg() {
    echo $1
}

set_group_name() {
    if [ "x" = "x${BUILD_GROUP}" ]; then
        local_groups=`${GROUPS_CMD}`
        BUILD_GROUP=`get_first_arg ${local_groups}`
    fi
}

initialize() { 
    # memorize current directory
    CURRENT_DIR=`pwd`

    # change current directory
    cd_build_dir

    # Make prefix directory
    if [ ! -d ${PREFIX} ]; then
        mkdir -p ${PREFIX}
    fi
}

finalize() {
    cd ${CURRENT_DIR}
}

build_libbind() {
    local_bind_pkg=`\ls bind-*.tar.gz | tail -1`

    echo ">>> [info] making ${local_bind_pkg}"

    if [ "x" = "x${local_bind_pkg}" -o ! -f "${local_bind_pkg}" ]; then
        abort "bind package file(tar.gz) not found"
    fi  
    (   
        gzip -dc ${local_bind_pkg} | ${TAR_CMD} -xf - -C ${WORK} && \
        local_bind_dir=`\basename ${WORK}/bind*` && \
        cd ${WORK}/${local_bind_dir}/lib/bind/ && \
        ./configure \
            --prefix=${WORK}/tmp_install \
            --enable-threads \
            ${CONFIGURE_OPTION} && \
        ${MAKE_CMD} && \
        ${MAKE_CMD} install
    ) || abort "${local_bind_pkg} make failed"
    echo ">>> [info] ${local_bind_pkg} make successfully"
}

build_libmilter() {
    local_sendmail_pkg=`\ls sendmail.*.tar.gz | tail -1`

    echo ">>> [info] making ${local_sendmail_pkg}"

    if [ "x" = "x${local_sendmail_pkg}" -o ! -f "${local_sendmail_pkg}" ]; then
        abort "sendmail package file(tar.gz) not found"
    fi  
    (   
        gzip -dc ${local_sendmail_pkg} | ${TAR_CMD} -xf - -C ${WORK} && \
        local_sendmail_dir=`\basename ${WORK}/sendmail*` && \
        cat ./${MILTER_CONFIG} | \
            ${SED_CMD} -e "s|@prefix@|${WORK}/tmp_install|g" | \
            ${SED_CMD} -e "s|@user@|${BUILD_USER}|g" | \
            ${SED_CMD} -e "s|@group@|${BUILD_GROUP}|g" > ${WORK}/${local_sendmail_dir}/devtools/Site/site.config.m4 && \
        cd ${WORK}/${local_sendmail_dir}/libmilter/ && \
        ./Build && \
        ./Build install
    ) || abort "${local_sendmail_pkg} make failed"
    echo ">>> [info] ${local_sendmail_pkg} make successfully"
}

build_enma() {
    echo ">>> [info] making enma"
    (
        cd ../ && \
        ./configure \
            --prefix=${PREFIX} \
            --with-libmilter=${WORK}/tmp_install \
            --with-libbind=${WORK}/tmp_install \
            ${CONFIGURE_OPTION} && \
        ${MAKE_CMD}
    ) || abort "enma make failed"
    echo ">>> [info] enma make successfully"
}

build_all() {
    # Make working directory
    if [ -d ${WORK} ]; then
        rm -fr ${WORK}
    fi
    mkdir -p ${WORK}

    # Processor check
    if [ ${M64_FLAG} -ne 0 ]; then
        MILTER_CONFIG=site.config.m4.poll-m64
        CONFIGURE_OPTION="CFLAGS=-m64 LDFLAGS=-m64"
    else
        MILTER_CONFIG=site.config.m4.poll-generic
    fi

    # set user/group
    set_user_name
    set_group_name

    build_libbind
    build_libmilter
    build_enma

    echo "== Making completed successfully =="
}

install_enma() {
    echo ">>> [info] installing enma"
    (   
        cd ../ && \
        ${MAKE_CMD} ${MAKE_DRY_RUN_OPTION} install 
    ) || abort "enma installation failed"
    echo "== Installation completed successfully =="
}

clean_all() {
    # Remove working directory
    echo ">>> [info] cleaning working directory..."
    rm -fr ${WORK}
    echo "== Cleaning completed successfully =="
}

build_handler() {
    case $1 in
        build)
            build_all;;
        install)
            install_enma;;
        clean)
            clean_all;;
        *)
            usage;;
    esac
}

parse_argument() {
    # build if not specified argument
    local_build_action="build"
    
    while [ ! -z "$1" ]; do
        case $1 in
            --prefix=*)
                PREFIX=`echo $1 | ${SED_CMD} -e "s|.*=||"`;;
            -n)
                MAKE_DRY_RUN_OPTION="-n";;
            build|install|clean)
                local_build_action=$1;;
            *)
                usage;;
        esac
        shift
    done
    
    build_handler ${local_build_action}
}


##
## Main
##
initialize

parse_argument $@

finalize
