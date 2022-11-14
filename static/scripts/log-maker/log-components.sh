#! /bin/bash

# need to add 5 cases as per component variable
component=$1
erlang_version=$2
PPS=$3
case $component in 
		"Audit")
			echo "Starting Audit backup"
			ls;;
	    "GMC")
			echo "********** Site Build ********************************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/patchman.escripts
			echo "********** Starting GMC backup ***********************"
			echo "********** Task_Manager_State ************************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/mhs/task_manager_process_info.escripts
			echo "********** Store_Manager_State ***********************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/mhs/store_manager.escripts
			echo "********** Mapf_Path_Calculator **********************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/mhs/mapf_path_calculator.escripts
			echo "********** Mapf_data_validation *********************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/mhs/mapf_data_validation.escripts
			echo "********** Reservation_table ************************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/mhs/reservation_table.escripts
			echo "**********Reservation_mismatch.escripts *************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/mhs/reservation_mismatch.escripts
 			;;
		"Pick")
			echo "Starting PICK Backup"
			echo "********** Site_Build *******************************"
			sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/patchman.escripts
			
#read it from pps
			if [ "$PPS" != "a" ]
			then
				echo "********** PPS Binrec Data **********************"						
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/pps_crash/ppsbinrec.escripts $PPS
				echo "********** PPs Bin Data *************************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/pps_crash/ppsbin.escripts $PPS
				echo "********** PPS Seat Data ************************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/pps_crash/pps_seat.escripts $PPS
				echo "********** PPS State Data ***********************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/pps_crash/pps_state.escripts $PPS
				echo "********** PPS Crash Data ***********************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/pps_crash/pps_crash.escripts $PPS
				echo "********** PPS Node Data ************************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/pps_crash/pps_node.escripts $PPS
				echo "********** Order_Manager_State ******************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/order_manager_state.escripts
				echo "********** Order_Manager_Process ****************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/order_manager_process.escripts
				echo "********** Order_Manager_Backtrace **************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/order_manager_backtrace.escripts
				echo "********** Order_Manager_Min_Free_Bins **********"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/free_bin_dockstation.escripts

			else
				echo "********** Order_Manager_State ******************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/order_manager_state.escripts
				echo "********** Order_Manager_Process ****************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/order_manager_process.escripts
				echo "********** Order_Manager_Backtrace **************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/order_manager_backtrace.escripts
				echo "********** Order_Manager_Min_Free_Bins **********"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/pick/free_bin_dockstation.escripts
				# get_all ppsbinrec, ppsnode, ppsbin

			fi;;
 		"Platform")
 			echo "Starting PLATFORM Backup"
 			free -h;;
		"Put")
			if [ "$PPS" != "a" ]
			then
				echo "Starting PUT Backup"
				echo "********** Site Build ***************************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/patchman.escripts
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/put/put.escripts $PPS
			else
				echo "Starting PUT Backup"
				echo "********** Site Build ***************************"
				sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/patchman.escripts
				# sudo /opt/butler_server/$erlang_version/bin/escript /opt/component/escripts/put/put.escripts $PPS
			fi;;
  		*)
 			echo "Invalid Component"
esac