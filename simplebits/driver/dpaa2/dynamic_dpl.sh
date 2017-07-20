#
# Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
#

cat > script_help << EOF

script help :----->

	Run this script as
	". ./dynamic_dpl.sh dpmac.1 dpmac.2 -b ab:cd:ef:gh:ij:kl"

	Acceptable arguments are dpmac.x and -b

    -b [optional] = Specify the MAC base address and must be followed by
		    a valid MAC base address. If this option is there in
		    command line then MAC addresses to DPNIs will be given as:

		    Base address = ab:cd:ef:gh:ij:kl
				 + 00:00:00:00:00:0I
		                  -------------------
				   Actual MAC address

		    where I is the index of the argument

	  dpmac.x = This specify that 1 DPNI  (dpni.y) object will be created,
		    which will be connected to dpmac.x.
		    dpmac.x <-------connected----->dpni.y

		    If -b option is not given then MAC address will be as:

		    dpni.y = 00:00:00:00:00:x
		    where x is the ID of the dpmac.x

	By default, this script will create 16 DPBP, 8 DPIOs, 8 DPCON.

	Note: Please refer to dynamic_dpl_logs file for script logs

     Optional configuration parameters:

	Below "ENVIRONMENT VARIABLES" are exported to get user defined
	configuration"
	/**DPNI**:-->
		MAX_QUEUES         = max number of Rx/Tx Queues on DPNI.
					Set the parameter using below command:
					'export MAX_QUEUES=<Number of Queues>'
					where "Number of Queues" is an integer
					value "e.g export MAX_QUEUES=8"

		MAX_TCS             = maximum traffic classes for Rx/Tx both.
					Set the parameter using below command:
					'export MAX_TCS=<Num of traffic class>'
					where "Number of traffic classes" is an
					integer value. "e.g export MAX_TCS=4"

		DPNI_OPTIONS        = DPNI related options.
					Set the parameter using below command:
					'export DPNI_OPTIONS="opt-1,opt-2,..."'
					e.g export DPNI_OPTIONS="DPNI_OPT_TX_FRM_RELEASE,DPNI_OPT_HAS_KEY_MASKING"

	/**DPCON**:-->
		DPCON_COUNT	    = DPCONC objects count
					Set the parameter using below command:
					'export DPCON_COUNT=<Num of dpconc objects>'
					where "Number of dpconc objects" is an
					integer value and greater than 2.
					e.g export DPCON_COUNT=10"

		DPCON_PRIORITIES    = number of priorities 1-8.
					Set the parameter using below command:
					'export DPCON_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					e.g export DPCON_PRIORITIES=8."

	/**DPIO**:-->
		DPIO_COUNT	    = DPIO objects count
					Set the parameter using below command:
					'export DPIO_COUNT=<Num of dpio objects>'
					where "Number of dpio objects" is an
					integer value.
					e.g export DPIO_COUNT=10"

		DPIO_PRIORITIES     = number of  priority from 1-8.
					Set the parameter using below command:
                                        'export DPIO_PRIORITIES=<Num of prio>'
					where "Number of priorities" is an
					integer value.
					"e.g export DPIO_PRIORITIES=8"

	/**DPBP**:-->
		DPBP_COUNT	    = DPBP objects count
					Set the parameter using below command:
					'export DPBP_COUNT=<Num of dpbp objects>'
					where "Number of dpbp objects" is an
					integer value.
					e.g export DPBP_COUNT=4"
EOF

# Function, to intialize the DPNI related parameters
get_dpni_parameters() {
	if [[ -z "$MAX_QUEUES" ]]
	then
		MAX_QUEUES=8
	fi
	if [[ -z "$MAX_TCS" ]]
	then
		MAX_TCS=1
	fi
	if [[ -z "$FS_ENTRIES" ]]
	then
		FS_ENTRIES=16
	fi
	echo >> dynamic_dpl_logs
	echo  "DPNI parameters :-->" >> dynamic_dpl_logs
	echo -e "\tMAX_QUEUES = "$MAX_QUEUES >> dynamic_dpl_logs
	echo -e "\tMAX_TCS = "$MAX_TCS >> dynamic_dpl_logs
	echo -e "\tDPNI_OPTIONS = "$DPNI_OPTIONS >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

# Function, to intialize the DPCON related parameters
get_dpcon_parameters() {
	if [[ "$DPCON_COUNT" ]]
	then
		if [[ $DPCON_COUNT -lt 3 ]]
		then
			echo -e "\tDPCON_COUNT value should be greater than 2" >> dynamic_dpl_logs
			echo -e $RED"\tDPCON_COUNT value should be greater than 2"$NC
			return 1;
		fi

	else
		DPCON_COUNT=8
	fi
	if [[ -z "$DPCON_PRIORITIES" ]]
	then
		DPCON_PRIORITIES=2
	fi
	echo "DPCON parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPCON_PRIORITIES	= "$DPCON_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPCON_COUNT		= "$DPCON_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

# Function, to intialize the DPBP related parameters
get_dpbp_parameters() {
	if [[ -z "$DPBP_COUNT" ]]
	then
		DPBP_COUNT=16
	fi
	echo "DPBP parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPBP_COUNT = "$DPBP_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

# Function, to intialize the DPIO related parameters
get_dpio_parameters() {
	if [[ -z "$DPIO_COUNT" ]]
	then
		DPIO_COUNT=8
	fi
	if [[ -z "$DPIO_PRIORITIES" ]]
	then
		DPIO_PRIORITIES=2
	fi
	echo "DPIO parameters :-->" >> dynamic_dpl_logs
	echo -e "\tDPIO_PRIORITIES = "$DPIO_PRIORITIES >> dynamic_dpl_logs
	echo -e "\tDPIO_COUNT = "$DPIO_COUNT >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
}

# function, to create the actual MAC address from the base address
create_actual_mac() {
	last_octet=$(echo $2 | head -1 | cut -f6 -d ':')
	last_octet=$(printf "%d" 0x$last_octet)
	last_octet=$(expr $last_octet + $1)
	last_octet=$(printf "%0.2x" $last_octet)
	if [[ 0x$last_octet -gt 0xFF ]]
        then
		last_octet=$(printf "%d" 0x$last_octet)
		last_octet=`expr $last_octet - 255`
		last_octet=$(printf "%0.2x" $last_octet)
	fi
	ACTUAL_MAC=$(echo $2 | sed -e 's/..$/'$last_octet'/g')
}


# script's actual starting point
rm dynamic_dpl_logs > /dev/null 2>&1
rm dynamic_results > /dev/null 2>&1
unset BASE_ADDR
printf "%-21s %-21s %-25s\n" "Interface Name" "Endpoint" "Mac Address" > dynamic_results
printf "%-21s %-21s %-25s\n" "==============" "========" "==================" >> dynamic_results
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
if [[ $1 ]]
then
	echo "Available DPRCs" >> dynamic_dpl_logs
	restool dprc list >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	# Creation of DPRC*/
	export DPRC=$(restool -s dprc create dprc.1 --label="ODP's container" --options=DPRC_CFG_OPT_SPAWN_ALLOWED,DPRC_CFG_OPT_ALLOC_ALLOWED,DPRC_CFG_OPT_OBJ_CREATE_ALLOWED)

	DPRC_LOC=/sys/bus/fsl-mc/devices/$DPRC
	echo $DPRC "Created" >> dynamic_dpl_logs

	# Validating the arguments*/
	echo >> dynamic_dpl_logs
	echo "Validating the arguments....." >> dynamic_dpl_logs
	num=1
	max=`expr $# + 1`
	while [[ $num != $max ]]
	do
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 1`
			BASE_ADDR=$(echo ${!num} | egrep "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
			if [[ $BASE_ADDR ]]
			then
				echo >> dynamic_dpl_logs
				echo -e '\t'$BASE_ADDR" will be used as MAC's base address" >> dynamic_dpl_logs
				num=`expr $num + 1`
			else
				echo >> dynamic_dpl_logs
				echo -e "\tInvalid MAC base address" >> dynamic_dpl_logs
				echo >> dynamic_dpl_logs
				echo
				echo -e $RED"\tInvalid MAC base address"$NC
				echo
				restool dprc destroy $DPRC >> dynamic_dpl_logs
				echo >> dynamic_dpl_logs
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
			fi
			continue;
		fi
		TYPE=$(echo ${!num} | head -1 | cut -f1 -d '.')
		if [[ $TYPE != "dpmac" ]]
		then
			echo >> dynamic_dpl_logs
			echo -e "\tInvalid Argument \""${!num}"\"" >> dynamic_dpl_logs
			echo >> dynamic_dpl_logs
			echo
			echo -e $RED"\tInvalid Argument \""${!num}"\"" $NC
			echo
			restool dprc destroy $DPRC >> dynamic_dpl_logs
			cat script_help
			rm script_help
			echo
			[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
		fi
		num=`expr $num + 1`
	done

	# Getting parameters*/
	get_dpni_parameters
	get_dpcon_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	get_dpbp_parameters
	get_dpio_parameters
	RET=$?
	if [[ $RET == 1 ]]
	then
		restool dprc destroy $DPRC >> dynamic_dpl_logs
		echo
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi

	# Objects creation*/
	num=1
	max=`expr $# + 1`
	while [[ $num != $max ]]
	do
		echo >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		echo "####### Parsing argument number "$num" ("${!num}") #######" >> dynamic_dpl_logs
		echo >> dynamic_dpl_logs
		MAC_OCTET2=0
		OBJ=${!num}
		MAC_OCTET1=$(echo $OBJ | head -1 | cut -f2 -d '.');
		if [[ $BASE_ADDR ]]
		then
			create_actual_mac $num $BASE_ADDR
		else
			ACTUAL_MAC="00:00:00:00:"$MAC_OCTET2":"$MAC_OCTET1
		fi
		DPNI=$(restool -s dpni create --options=$DPNI_OPTIONS --num-tcs=$MAX_TCS --num-queues=$MAX_QUEUES --fs-entries=$FS_ENTRIES --container=$DPRC)
		restool dprc sync
		restool dpni update $DPNI --mac-addr=$ACTUAL_MAC
		echo -e '\t'$DPNI "created with MAC addr = "$ACTUAL_MAC >> dynamic_dpl_logs
		export DPNI$num=$DPNI
		MAC_ADDR2=$ACTUAL_MAC
		echo -e "\tDisconnecting the" $OBJ", if already connected" >> dynamic_dpl_logs
		TEMP=$(restool dprc disconnect dprc.1 --endpoint=$OBJ > /dev/null 2>&1)
		TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ 2>&1)
		CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
		if [[ $CHECK == "error:" ]]
		then
			echo -e "\tGetting error, trying to create the "$OBJ >> dynamic_dpl_logs
			OBJ_ID=$(echo $OBJ | head -1 | cut -f2 -d '.')
			TEMP=$(restool dpmac create --mac-id=$OBJ_ID 2>&1)
			CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
			if [[ $CHECK == "error:" ]]
			then
				echo -e "\tERROR: unable to create "$OBJ $NC >> dynamic_dpl_logs
				echo -e "\tDestroying container "$DPRC >> dynamic_dpl_logs
				echo -e $RED"\tERROR: unable to create "$OBJ $NC
				./destroy_dynamic_dpl.sh $DPRC >> dynamic_dpl_logs
				echo
				rm script_help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
			fi
			restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ
		fi
		MAC_ADDR1=
		echo -e '\t'$OBJ" Linked with "$DPNI >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPNI --child=$DPRC --plugged=1)
		echo -e '\t'$DPNI "moved to plugged state " >> dynamic_dpl_logs
		if [[ $MAC_ADDR1 ]]
		then
			if [[ $MAC_ADDR2 ]]
			then
				printf "%-21s %-21s %-25s\n" $DPNI $OBJ $MAC_ADDR2 >> dynamic_results
			fi
			printf "%-21s %-21s %-25s\n" $OBJ $DPNI $MAC_ADDR1 >> dynamic_results
		elif [[ $OBJ ]]
		then
			printf "%-21s %-21s %-25s\n" $DPNI $OBJ $MAC_ADDR2 >> dynamic_results
		else
			printf "%-21s %-21s %-25s\n" $DPNI "UNCONNECTED" $MAC_ADDR2 >> dynamic_results
		fi
		OBJ=
		num=`expr $num + 1`
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 2`
			continue;
		fi
	done
	echo >> dynamic_dpl_logs
	echo "******* End of parsing ARGS *******" >> dynamic_dpl_logs
	echo >> dynamic_dpl_logs
	restool dprc sync

	# DPBP objects creation*/
	for i in $(seq 1 ${DPBP_COUNT}); do
		DPBP=$(restool -s dpbp create --container=$DPRC)
		echo $DPBP "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPBP --child=$DPRC --plugged=1)
		echo $DPBP "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	# DPCON objects creation*/
	for i in $(seq 1 ${DPCON_COUNT}); do
		DPCON=$(restool -s dpcon create --num-priorities=$DPCON_PRIORITIES --container=$DPRC)
		echo $DPCON "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPCON --child=$DPRC --plugged=1)
		echo $DPCON "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	# DPIO objects creation*/
	for i in $(seq 1 ${DPIO_COUNT}); do
		DPIO=$(restool -s dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES --container=$DPRC)
		echo $DPIO "Created" >> dynamic_dpl_logs
		restool dprc sync
		TEMP=$(restool dprc assign $DPRC --object=$DPIO --child=$DPRC --plugged=1)
		echo $DPIO "moved to plugged state" >> dynamic_dpl_logs
		restool dprc sync
	done;

	if [ -e $DPRC_LOC ];
	then
		echo sb_dpaa2 > /sys/bus/fsl-mc/devices/$DPRC/driver_override
		echo -e "\tBind "$DPRC" to VFIO driver" >> dynamic_dpl_logs
	fi
	dmesg -E

	echo -e "##################### Container $GREEN $DPRC $NC is created ####################"
	echo
	echo -e "Container $DPRC have following resources :=>"
	echo
	count=$(restool dprc show $DPRC | grep -c dpbp.*)
	echo -e " * $count DPBP"
	count=$(restool dprc show $DPRC | grep -c dpcon.*)
	echo -e " * $count DPCON"
	count=$(restool dprc show $DPRC | grep -c dpni.*)
	echo -e " * $count DPNI"
	count=$(restool dprc show $DPRC | grep -c dpio.*)
	echo -e " * $count DPIO"
	echo
	echo
	unset count
	echo -e "######################### Configured Interfaces #########################"
	echo
	cat dynamic_results
	echo >> dynamic_dpl_logs
	echo -e "USE " $DPRC " FOR YOUR APPLICATIONS" >> dynamic_dpl_logs
	rm script_help
	echo
else
	echo >> dynamic_dpl_logs
	echo -e "\tArguments missing" >> dynamic_dpl_logs
	echo
	echo -e '\t'$RED"Arguments missing"$NC
	cat script_help
	rm script_help
fi
