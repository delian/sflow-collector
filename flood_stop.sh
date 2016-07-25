#!/bin/bash
LOG="/home/delian/sflow-collector/flood.log"
echo "`date "+%H:%M:%S %d.%m.%Y"` flood_stop.sh  - Stop , IP=$1" >>  $LOG
# /usr/local/bin/flood_alarm.sh $1 0
/usr/bin/curl "http://monitor.net-surf.net/zabbix_posts/sflow_aparms.php?ipaddr=${1}&state=0"

#remove filter
/usr/bin/sudo -u serv /home/serv/intl_blackhole.sh ${1} blackhole_rem >> /dev/null