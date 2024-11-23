#!/bin/bash

set -exo pipefail

# Display Help
function help {
cat << EOF
    The script provides tooling for resque operations (e.g data backup, data restore) of mariadb
    galera cluster member.
    Currently supported:
        - physical data backup and restore using mariabackup.
    Example of resulting backup directory structure:

    /var/backup
    |-- base
    |   |-- 2020-07-30_10-00-07
    |   |-- 2020-07-30_10-00-17
    |   |-- 2020-07-30_10-18-43
    |-- incr
    |   |-- 2020-07-30_10-00-17
    |       |-- 2020-07-30_10-00-36
    |       |-- 2020-07-30_10-03-37

    Usage:
      backup [--mariadb-host=<host>]             - ip address or host name of mariadb server (default localhost)
             [--required-space-ratio=<number>]   - is a multiplier (floating number e.g 1.2) for predicting space needed
                                                   to create backup and then to do a restore keeping uncompressed backup files
                                                   on the same filesystem as compressed ones. To estimate how big REQUIRED_SPACE_RATIO the next
                                                   formula can be used:
                                                     size of (1 uncompressed full backup + all related incremental uncompressed backups + 1
                                                     full compressed backup) in KB =< (DB_SIZE * REQUIRED_SPACE_RATIO) in KB
                                                   (default 1.2)

             [--target-dir=<path>]               - directory where to save backup e.g base/2020-07-30_10-00-07 or incr/2020-07-30_10-00-17/2020-07-30_10-00-36


             [--incremental-base-dir=<path>]     - directory to take info about base backup, used only in case of incremental backup e.g base/2020-07-30_10-00-07
                                                   or incr/2020-07-30_10-00-17/2020-07-30_10-00-36

             [--mariadb-client-conf=<path>]      - path on file system to file with mysql client settings (user, password) (default /etc/mysql/mariabackup_user.cnf)

             [--validate=(True|False)]           - Whether to run just validation or make a backup
             [--openssl-encryption=(True|False)] - Whether to encrypt backup stream with openssl encryption

      restore --backup-name=<name>                      - (required) name of directory with full backup to restore e.g 2020-07-29_10-31-52, all
                                                          related incremental backups also have full backup name in the path. In order to restore
                                                          specific incremental backup (and all previous incrementals) specify it after slash e.g:
                                                          2020-07-29_10-31-52/2020-07-30_10-31-52.


              [--mariadb-client-conf=<path>]            - path on file system to file with mysql client settings (user, password) (default /etc/mysql/mariabackup_user.cnf)

              [--validate=(True|False)]                 - Whether to run just validation or make a restore

      cleanup [--cleanup-unarchieved-data=(True|False)]     - whether to cleanup earlier unarchieved data

              [--cleanup-mysql-data=(True|False)           - whether to cleanup mysql data directory

      -h - output this help message
EOF
}

# Prints line number and "message" in error format
# err $LINENO "message"
function err {
    local exitcode=$?
    local xtrace
    xtrace=$(set +o | grep xtrace)
    set +o xtrace
    local msg="[ERROR] ${BASH_SOURCE[2]}:$1 $2"
    echo "$msg" 1>&2;
    $xtrace
    return $exitcode
}

# Prints backtrace info
# filename:lineno:function
# backtrace level
function backtrace {
    local level=$1
    local deep
    deep=$((${#BASH_SOURCE[@]} - 1))
    echo "[Call Trace]"
    while [[ ${level} -le ${deep} ]]; do
        echo "${BASH_SOURCE[$deep]}:${BASH_LINENO[$deep-1]}:${FUNCNAME[$deep-1]}"
        deep=$((deep - 1))
    done
}

# Prints line number and "message" then exits
# die $LINENO "message"
function die {
    local exitcode=$?
    set +o xtrace
    local line=$1; shift
    if [[ "${exitcode}" == 0 ]]; then
        exitcode=1
    fi
    backtrace 2
    err "${line}" "$*"
    # Give buffers a second to flush
    sleep 1
    exit $exitcode
}

# checks that arg 1 match regex 2
function check_optional_arg {
    if [[ ! ${1} =~ ${2} ]]; then
        help
        die $LINENO "Some parameter is set to incorrect value."
    fi
}


OPERATION=$1

case $OPERATION in
    cleanup)
    echo "Running mariadb data cleanup"
    shift
    for i in "$@"; do
        case $i in
            --cleanup-mysql-data=*)
            CLEANUP_MYSQL_DATA="${i#*=}"
            check_optional_arg "${CLEANUP_MYSQL_DATA}" "(^True$|^False$)"
            shift
            ;;
            --cleanup-unarchieved-data=*)
            CLEANUP_UNARCHIEVED_DATA="${i#*=}"
            check_optional_arg "${CLEANUP_UNARCHIEVED_DATA}" "(^True$|^False$)"
            shift
            ;;
            *)
            help
            die $LINENO "Unsupported cleanup option"
            ;;
        esac
    done
    ;;
    restore)
    echo "Running mariadb physical restore"
    shift
    for i in "$@"; do
        case $i in
            --backup-name=*)
            MARIADB_BACKUP_NAME="${i#*=}"
            if [[ ! "${MARIADB_BACKUP_NAME}" ]]; then
                die $LINENO "Target backup name is undefined"
            fi
            shift
            ;;
            --mariadb-client-conf=*)
            MARIADB_CLIENT_CONF="${i#*=}"
            shift
            ;;
            --validate=*)
            VALIDATE="${i#*=}"
            check_optional_arg "${VALIDATE}" "(^True$|^False$)"
            shift
            ;;
            *)
            help
            die $LINENO "Unsupported restore option"
            ;;
        esac
    done
    ;;
    backup)
    echo "Running mariadb physical backup"
    shift
    for i in "$@"; do
        case $i in
            --target-dir=*)
            TARGET_DIR="${i#*=}"
            shift
            ;;
            --incremental-base-dir=*)
            INCREMENTAL_BASE_DIR="${i#*=}"
            shift
            ;;
            --mariadb-host=*)
            MARIADB_HOST="${i#*=}"
            shift
            ;;
            --required-space-ratio=*)
            REQUIRED_SPACE_RATIO="${i#*=}"
            shift
            ;;
            --mariadb-client-conf=*)
            MARIADB_CLIENT_CONF="${i#*=}"
            shift
            ;;
            --validate=*)
            VALIDATE="${i#*=}"
            check_optional_arg "${VALIDATE}" "(^True$|^False$)"
            shift
            ;;
            --openssl-encryption=*)
            OPENSSL_ENCRYPTION="${i#*=}"
            check_optional_arg "${OPENSSL_ENCRYPTION}" "(^True$|^False$)"
            shift
            ;;
            *)
            help
            die $LINENO "Unsupported backup option"
            ;;
        esac
    done
    ;;
    -h)
    help
    exit 0
    ;;
    *)
    help
    die $LINENO "Unsupported operation"
    ;;
esac

function lock {
    if [[ -d "${LOCKDIR}" ]]; then
        die $LINENO "Lock directory ${LOCKDIR} already exists"
    else
        mkdir "${LOCKDIR}" || die $LINENO "Could not create lock directory ${LOCKDIR}"
        echo "Lock directory created. Check completed."
    fi
}

function unlock {
    if [[ -d "${LOCKDIR}" ]]; then
        if rmdir "${LOCKDIR}"; then
            echo "Lock directory ${LOCKDIR} removed"
        else
            die $LINENO "Unable to remove lock directory ${LOCKDIR}"
        fi
    else
       echo "Lock directory ${LOCKDIR} does not exist, nothing to unlock"
    fi
}

function post_operation_info(){
    SPENT=$(( $(date +%s) - START ))
    echo "Took ${SPENT} seconds. Completed: $(date)"
    for d in ${BACKDIR} /var/lib/mysql; do
        if [[ -d ${d} ]]; then
            echo "${d} directories tree:"
            tree -d "${d}"
            du -sh ${d}
        fi
    done
}

function set_global_variables(){
    BACKCMD=mariabackup
    BACKDIR=/var/backup
    LOCKDIR="${BACKDIR}/mariabackup.lock"
    MARIADB_CLIENT_CONF=${MARIADB_CLIENT_CONF:-/etc/mysql/mariabackup_user.cnf}
    USEROPTIONS="--defaults-file=${MARIADB_CLIENT_CONF}"
    BASEBACKDIR="${BACKDIR}/base"
    INCRBACKDIR="${BACKDIR}/incr"
    START=$(date +%s)
    OPENSSL_ENCRYPTION=${OPENSSL_ENCRYPTION:-"False"}
    OPENSSL_KEK_FILE=${OPENSSL_KEK_FILE:-"/etc/mysql/backup-kek"}
    OPENSSL_DEK_FILE_NAME="dek.enc"
    BACKUP_STREAM_FILENAME="backup.stream.gz"

    if [[ $OPERATION == 'backup' ]]; then
        MARIADB_HOST=${MARIADB_HOST:-localhost}
        USEROPTIONS="${USEROPTIONS} --host=${MARIADB_HOST}"
        REQUIRED_SPACE_RATIO=${REQUIRED_SPACE_RATIO:-'1.2'}
    elif [[ $OPERATION == 'restore' ]]; then
        if [[ "${MARIADB_BACKUP_NAME}" =~ ^.*/.*$ ]]; then
            TARGET_BASE_BACKUP_NAME="$(echo ${MARIADB_BACKUP_NAME} | cut -d/ -f1)"
            TARGET_INCR_BACKUP_NAME="$(echo ${MARIADB_BACKUP_NAME} | cut -d/ -f2)"
        else
            TARGET_BASE_BACKUP_NAME="${MARIADB_BACKUP_NAME}"
        fi
        TARGET_BASE_BACKUP_DIR="${BASEBACKDIR}/${TARGET_BASE_BACKUP_NAME}"
        if [[ ! -d "${TARGET_BASE_BACKUP_DIR}" ]]; then
            die $LINENO "Target backup directory ${TARGET_BASE_BACKUP_DIR} does not exist"
        fi
        local incr_parent_path="${INCRBACKDIR}/${TARGET_BASE_BACKUP_NAME}"

        if [[ "${TARGET_INCR_BACKUP_NAME}" ]]; then
            local incr_dirs
            local incr_parent_path="${INCRBACKDIR}/${TARGET_BASE_BACKUP_NAME}"
            [[ -d "${incr_parent_path}" ]] || die $LINENO "Incremental backups parent directory ${incr_parent_path} not found"
            incr_dirs=$(find ${incr_parent_path} -name ${BACKUP_STREAM_FILENAME} | xargs dirname | sort -n)
            local target_incr_backup_path="${incr_parent_path}/${TARGET_INCR_BACKUP_NAME}"
            local num

            echo "Restore to specific incremental backup was requested.
                  Searching incremental backup ${target_incr_backup_path} among ${incr_dirs}
                  and all previous incremental backups if any."
            # All backups till target backup and including it
            num=$(echo "${incr_dirs}" | grep -n -E ^"${target_incr_backup_path}"$ | cut -d: -f1)
            [[ "${num}" ]] || die $LINENO "Incremental backup ${target_incr_backup_path} not found!"
            TARGET_INCR_BACKUP_DIRS=$(echo "${incr_dirs}" | head "-${num}")
        fi
    fi
}

function pre_backup_sanity_check() {
    local available_space
    local db_size
    local required_space
    mysql $USEROPTIONS -s -e 'exit' || die $LINENO "FATAL ERROR: Could not connect to mysql with provided credentials"
    # check available space on device in KB
    available_space=$(df --output=avail -k ${BACKDIR} | sed 's/[^0-9]*//g' | tr -d '[:space:]')
    # Calculate current db size
    db_size=$(du -s --exclude=galera.cache --exclude=ib_logfile* /var/lib/mysql | sed 's/[^0-9]*//g' | tr -d '[:space:]')
    required_space=$(echo | awk "{ printf \"%.f\", $db_size*$REQUIRED_SPACE_RATIO }")
    if [[ $available_space -lt $required_space ]]; then
        die $LINENO "FATAL ERROR: Not enough space for backup,
                     AVAILABLE_SPACE is ${available_space},
                     DB_SIZE is ${db_size},
                     REQUIRED_SPACE is ${required_space}"
    fi
}

function run_backup() {

    TARGET_PATH="${BACKDIR}/${TARGET_DIR}"
    if [[ ${INCREMENTAL_BASE_DIR} ]]; then
        INCREMENTAL_BASE_PATH="${BACKDIR}/${INCREMENTAL_BASE_DIR}"
        BACKUP_OPTIONS="${USEROPTIONS} --backup --extra-lsndir=${TARGET_PATH} --incremental-basedir=${INCREMENTAL_BASE_PATH} --stream=xbstream"
    else
        BACKUP_OPTIONS="${USEROPTIONS} --backup --extra-lsndir=${TARGET_PATH} --stream=xbstream"
    fi

    mkdir -p "${TARGET_PATH}"

    if [[ "${OPENSSL_ENCRYPTION}" == "True" ]]; then
        openssl rand -hex 32 > ${TARGET_PATH}/${OPENSSL_DEK_FILE_NAME}.plain
        $BACKCMD $BACKUP_OPTIONS | gzip |openssl enc -aes-256-cbc -pbkdf2 -pass file:${TARGET_PATH}/${OPENSSL_DEK_FILE_NAME}.plain > "${TARGET_PATH}/${BACKUP_STREAM_FILENAME}"
        openssl enc -aes-256-cbc -pbkdf2 -pass file:${OPENSSL_KEK_FILE} -in ${TARGET_PATH}/${OPENSSL_DEK_FILE_NAME}.plain -out ${TARGET_PATH}/${OPENSSL_DEK_FILE_NAME}
        rm -f ${TARGET_PATH}/${OPENSSL_DEK_FILE_NAME}.plain
    else
        $BACKCMD $BACKUP_OPTIONS | gzip > "${TARGET_PATH}/${BACKUP_STREAM_FILENAME}"
    fi
    # backup original grastate.dat to make sure that restore will be done correctly,
    # xtrabackup_galera_info doesn't contain all fields from grastate.dat
    cp /var/lib/mysql/grastate.dat "${TARGET_PATH}/"
    touch "${TARGET_PATH}/backup.successful"
}

function decompress() {
    local dst="${1}/unarchieved"
    if [[ -d ${dst} ]]; then
        echo "Unarchive directory ${dst} exist. Wiping it."
        rm -rf ${dst}/*
    fi
    mkdir -p "${dst}"
    if file "${1}/${BACKUP_STREAM_FILENAME}" |grep openssl; then
        openssl enc -d -aes-256-cbc -pbkdf2 -pass file:${OPENSSL_KEK_FILE} -in "$1/${OPENSSL_DEK_FILE_NAME}" > "$1/${OPENSSL_DEK_FILE_NAME}.plain"
        openssl enc -d -aes-256-cbc -pbkdf2 -pass file:"$1/${OPENSSL_DEK_FILE_NAME}.plain" -in "${1}/${BACKUP_STREAM_FILENAME}" |gzip -d| mbstream -x -C "${dst}"
        rm -f "$1/${OPENSSL_DEK_FILE_NAME}.plain"
    else
        zcat "${1}/${BACKUP_STREAM_FILENAME}" | mbstream -x -C "${dst}"
    fi
}

function unarchieve_backups() {
    for dir in ${TARGET_BASE_BACKUP_DIR}; do
        decompress $dir
    done
    if [[ -n "${TARGET_INCR_BACKUP_DIRS}" ]]; then
        for dir in ${TARGET_INCR_BACKUP_DIRS}; do
            decompress $dir
        done
    fi
}

function prepare_backup_for_restore(){
    # prepare backups, the first directory in BACKUP_DIRS is the directory with full backup, other lines may contain
    # directories with incremental backups
    ${BACKCMD} --prepare --target-dir "${TARGET_BASE_BACKUP_DIR}/unarchieved/"
    for dir in ${TARGET_INCR_BACKUP_DIRS}; do
        echo "Preparing incremental backup ${dir}"
        ${BACKCMD} --prepare --target-dir "${TARGET_BASE_BACKUP_DIR}/unarchieved/" --incremental-dir="${dir}/unarchieved"
    done
    touch "${TARGET_BASE_BACKUP_DIR}/.prepared"
}

function run_restore() {
    # TODO: implement rollback of restore
    # mariabackup requires datadir to be clean
    local latest_grastate_file
    if [[ ! "${TARGET_INCR_BACKUP_DIRS}" ]]; then
        echo "NO incremental backups found for base backup ${TARGET_BASE_BACKUP_DIR}, only base backup will be restored"
        latest_grastate_file=${TARGET_BASE_BACKUP_DIR}/grastate.dat
    else
        latest_grastate_file=$(echo "${TARGET_INCR_BACKUP_DIRS}" | tail -n 1)/grastate.dat
    fi
    ${BACKCMD} ${USEROPTIONS} --copy-back --target-dir "${TARGET_BASE_BACKUP_DIR}/unarchieved/" --datadir /var/lib/mysql
    cp "${latest_grastate_file}" /var/lib/mysql
}

function cleanup_unarchieved_data(){

    for dirname in ${BASEBACKDIR} ${INCRBACKDIR}; do
        if [[ ! -e "${dirname}" ]]; then
            continue
        fi

        unarchieved=$(find "${dirname}" -name unarchieved -type d)
        prepared=$(find "${dirname}" -name .prepared -type f)

        for dir in ${unarchieved}; do
            rm -rf "${dir}"
        done
        for file in ${prepared}; do
            rm -f "${file}"
        done
    done
}

function get_mariabackup_version() {
    echo "$(${BACKCMD} --version 2>&1 | sed -nE 's/.*(10\.[0-9]{1,2}\.[0-9]{1,2}-MariaDB).*/\1/p')"
}

function get_backup_version() {
    local backup=$1
    # if function called without params, we looking for latest full backup and return its version
    if [[ ! ${backup} ]]; then
        backup=$(find ${BASEBACKDIR} -mindepth 1 -name xtrabackup_info -printf "%h\n" | sort | tail -1)
    fi
    if [[ ! ${backup} ]]; then
        echo "No-backups"
    else
        echo "$(cat ${backup}/xtrabackup_info | grep tool_version | cut -d' ' -f3)"
    fi
}

function pre_restore_sanity_check() {
    local tools_version=$(get_mariabackup_version)
    local backup_version=$(get_backup_version "${TARGET_BASE_BACKUP_DIR}")
    if [[ "${tools_version%.*}" != "${backup_version%.*}" ]]; then
        die $LINENO "Backup need ${backup_version} for restore but we have ${tools_version}"
    fi
}

# Exit on any errors so that errors don't compound and make cleanup
trap err_trap EXIT
function err_trap {
    local r=$?
    if [[ $r -ne 0 ]]; then
        set +o xtrace
        post_operation_info
        unlock
        echo "${0##*/} FAILED"
    fi
    exit $r
}

echo "started: $(date)"
echo

set_global_variables

case $OPERATION in

    backup)

        lock

        if [[ $VALIDATE == 'True' ]]; then
            pre_backup_sanity_check
        else
            run_backup
        fi

        unlock
        ;;

    restore)

        lock

        if [[ $VALIDATE == 'True' ]]; then
            pre_restore_sanity_check
        else
            if [[ ! -f "${TARGET_BASE_BACKUP_DIR}/.prepared" ]]; then
                unarchieve_backups
                prepare_backup_for_restore
            fi
            run_restore
        fi

        unlock
        ;;

    cleanup)

        if [[ "${CLEANUP_UNARCHIEVED_DATA}" == 'True' ]]; then
            cleanup_unarchieved_data
        fi

        if [[ "${CLEANUP_MYSQL_DATA}" == 'True' ]]; then
            rm -rf /var/lib/mysql/*
        fi
        ;;
esac

post_operation_info
