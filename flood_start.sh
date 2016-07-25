#!/bin/bash
LOG="/home/delian/sflow-collector/flood.log"
echo "`date "+%H:%M:%S %d.%m.%Y"` flood_start.sh  - Start , IP=$1" >>  $LOG
#/usr/local/bin/flood_alarm.sh "$1" "1"

#zabbix alarm
/usr/bin/curl "http://monitor.net-surf.net/zabbix_posts/sflow_aparms.php?ipaddr=${1}&state=1"

#add filter {IP} {blackhole_add|blackhole_rem}
/usr/bin/sudo -u serv /home/serv/intl_blackhole.sh ${1} blackhole_add >> /dev/null