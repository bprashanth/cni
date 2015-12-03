#!/bin/bash

NETCONFPATH=${NETCONFPATH-/etc/cni/net.d}

function exec_plugins() {
	i=0
	contid=$2
	netns=$3
	export CNI_COMMAND=$(echo $1 | tr '[:lower:]' '[:upper:]')
	export PATH=$CNI_PATH:$PATH
	export CNI_CONTAINERID=$contid
	export CNI_NETNS=$netns

	for netconf in $(echo $NETCONFPATH/*.conf | sort); do
		name=$(jq -r '.name' <$netconf)
		plugin=$(jq -r '.type' <$netconf)
		export CNI_IFNAME=$(printf eth%d $i)
        echo operation=$CNI_COMMAND name=$name plugin=$plugin CNI_IFNAME=$CNI_IFNAME CNI_CONTAINERID=$CNI_CONTAINERID CNI_NETNS=$CNI_NETNS
        echo Execing: $plugin `cat $netconf`
		res=$($plugin <$netconf)
        echo Result from $plugin: $res
		if [ $? -ne 0 ]; then
			errmsg=$(echo $res | jq -r '.msg')
			if [ -z "$errmsg" ]; then
				errmsg=$res
			fi

			echo "${name} : error executing $CNI_COMMAND: $errmsg"
			exit 1
		fi

		let "i=i+1"
	done
}

if [ $# -ne 3 ]; then
	echo "Usage: $0 add|del CONTAINER-ID NETNS-PATH"
	echo "  Adds or deletes the container specified by NETNS-PATH to the networks"
	echo "  specified in \$NETCONFPATH directory"
	exit 1
fi

exec_plugins $1 $2 $3
