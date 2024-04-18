#!/bin/bash

ARGC=$#
EXPORTER=/opt/MESA/bin/fieldstat_exporter.py
TARGET=/opt/tsg/verify-policy/log/maat_stat.db.1

case $1 in
    -h|--help)
        echo "$0"
        echo "Usage: [exporter] [target]"
        echo "  exporter: path of exporter, default is $EXPORTER"
        echo "  target: path of target file, default is $TARGET"
        exit 0
        ;;
esac

case $ARGC in
  	1)
		EXPORTER=$1
	  ;;
  	2)
		EXPORTER=$1
		TARGET=$2
	  ;;
esac

 python3 $EXPORTER local -j $TARGET -e -t '
    {{ 
        print_tables
        ( 
            "TBL", 
                [   
                    "rule", 
                    "reg/v6",
                    "scan_times",
                    "hit_times",
                    "scan_bytes",
                    "scan_cpu_time",
                    "hit_item_num",
                    "hit_pat_num",
                    "#Name<IN_Bps>#Ratio<scan_bytes,scan_cpu_time,100>",
                    "#Name<hit_rate>#Ratio<hit_times,scan_times,1>"
                ],
                False
        )
    }}
'
