#!/bin/bash
set -e

### BEGIN INIT INFO
# Provides:          neptun2mqtt
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Neptun ProW - MQTT bridge
# Description:       Neptun ProW - MQTT bridge
### END INIT INFO

DIR=/home/pi/neptun2mqtt
DAEMON=/usr/bin/python3
DAEMON_NAME=neptun2mqtt
DAEMON_LOG=/var/log/neptun2mqtt.log
USER="root"

# Add any command line options for your daemon here
DAEMON_OPTS="$DIR/neptun2mqtt.py"

# This next line determines what user the script runs as.
# Root generally not recommended but necessary
DAEMON_USER=root

# The process ID of the script when it runs is stored here:
PIDFILE=/var/run/$DAEMON_NAME.pid

. /lib/lsb/init-functions

get_pid() {
    cat "$PIDFILE"
}

is_running() {
    [ -f "$PIDFILE" ] && ps -p `get_pid` > /dev/null 2>&1
}

do_start () {
    if is_running; then
        echo -n "Already started">&2
    else
        echo -n "Starting "$DAEMON_NAME>&2
        echo -n "Starting "$DAEMON_NAME>&1
        echo "Starting ">&1
        echo "Starting ">&2
        log_action_msg "Starting "$DAEMON_NAME
        log_daemon_msg "Starting system $DAEMON_NAME daemon"
        start-stop-daemon -v -quiet --start --background --pidfile $PIDFILE --make-pidfile --user $DAEMON_USER --chuid $DAEMON_USER --startas $DAEMON -- $DAEMON_OPTS 2>&1
        log_end_msg $?
    fi
}
do_stop () {
    echo -n "Stopping "$DAEMON_NAME>&2
    log_daemon_msg "Stopping system $DAEMON_NAME daemon"
    start-stop-daemon --stop --pidfile $PIDFILE --retry 10
    log_end_msg $?
}

case "$1" in

    start|stop)
        do_${1}
        ;;

    restart|reload|force-reload)
        do_stop
        do_start
        ;;

    status)
        status_of_proc "$DAEMON_NAME" "$DAEMON" && exit 0 || exit $?
        ;;

    *)
        echo "Usage: /etc/init.d/$DAEMON_NAME {start|stop|restart|status}"
        exit 1
        ;;

esac
exit 0