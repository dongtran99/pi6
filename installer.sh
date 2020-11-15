#!/bin/bash

echo ""
echo -en "\033[37;1;41m Script for automatic configuration of IPv6 proxy. \033[0m"
echo ""
echo ""
echo -en "\033[37;1;41m VPS server hosting - VPSVille.ru \033[0m"
echo -en "\033[37;1;41m IPv6 networks - / 64, / 48, / 36, / 32 under a proxy. \033[0m"
echo ""
echo ""
echo -en "\033[37;1;41m ATTENTION \033[0m"
echo ""
echo -en "\033[37;1;41m This script configures IPv6 proxies in automatic mode only based on Debian 8 \033[0m"
echo ""
echo ""

read -p "Press [Enter] to continue ..."

echo ""
echo "IPv6 proxy configuration"
echo ""

echo "Enter the given network and press [ENTER]:"
read network
if [[ $network == *"::/48"* ]]
then
    mask=48
elif [[ $network == *"::/64"* ]]
then
    mask=64
elif [[ $network == *"::/32"* ]]
then
    mask=32
    echo "Enter network / 64, this is the gateway required to connect to the / 32 network. The / 64 network is connected in your personal account in the section - Network."
    read network_mask
elif [[ $network == *"::/36"* ]]
then
    mask=36
    echo "Enter the network / 64, this is the gateway required to connect the network / 36. The / 64 network is connected in your personal account in the section - Network."
    read network_mask
else
    echo "Unrecognized mask or invalid network format, enter network with mask / 64, / 48, / 36 or / 32"
    exit 1
fi
echo "Enter the number of addresses to randomly generate"
read MAXCOUNT
THREADS_MAX=`sysctl kernel.threads-max|awk '{print $3}'`
MAXCOUNT_MIN=$(( MAXCOUNT-200 ))
if (( MAXCOUNT_MIN > THREADS_MAX )); then
    echo "kernel.threads-max = $THREADS_MAX this is not enough for the specified number of addresses!"
fi

echo "Enter login for proxy"
read proxy_login
echo "Enter your proxy password"
read proxy_pass
echo "Enter the starting port for the proxy"
read proxy_port

base_net=`echo $network | awk -F/ '{print $1}'`
base_net1=`echo $network_mask | awk -F/ '{print $1}'`

echo "Configuring a proxy for the $base_net network with a $mask"
sleep 2
echo "Setting the IPv6 base address"
ip -6 addr add ${base_net}2 peer ${base_net}1 dev eth0
sleep 5
ip -6 route add default via ${base_net}1 dev eth0
ip -6 route add local ${base_net}/${mask} dev lo

echo "Checking IPv6 connectivity ..."
if ping6 -c3 google.com &> /dev/null
then
    echo "Successfully"
else
    echo "Warning: IPv6 connectivity does not work!"
fi


echo "Copying executable files"

if [ -f /root/3proxy.tar ]; then
   echo "The archive 3proxy.tar has already been downloaded, we continue to configure ..."
else
   echo "The archive 3proxy.tar is missing, downloading ..."
   wget https://blog.vpsville.ru/uploads/3proxy.tar; tar -xvf 3proxy.tar
fi

if [ -f /root/ndppd.tar ]; then
   echo "The ndppd.tar archive has already been downloaded, let's continue with the configuration ..."
else
   echo "The ndppd.tar archive is missing, downloading ..."
   wget https://blog.vpsville.ru/uploads/ndppd.tar; tar -xvf ndppd.tar
fi


echo "Configuring ndppd"
mkdir -p /root/ndppd/
rm -f /root/ndppd/ndppd.conf
cat >/root/ndppd/ndppd.conf <<EOL
route-ttl 30000
proxy eth0 {
   router no
   timeout 500   
   ttl 30000
   rule __NETWORK__ {
      static
   }
}
EOL
sed -i "s/__NETWORK__/${base_net}\/${mask}/" /root/ndppd/ndppd.conf

echo "Configuring 3proxy"
rm -f /root/ip.list
echo "Generating $MAXCOUNT addresses "
array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
count=1
first_blocks=`echo $base_net|awk -F:: '{print $1}'`
rnd_ip_block ()
{
    a=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    b=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    c=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    d=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
    if [[ "x"$mask == "x48" ]]
    then
        e=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        echo $first_blocks:$a:$b:$c:$d:$e >> /root/ip.list
    elif [[ "x"$mask == "x32" ]]
    then
        e=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        f=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        echo $first_blocks:$a:$b:$c:$d:$e:$f >> /root/ip.list
    elif [[ "x"$mask == "x36" ]]
    then
        num_dots=`echo $first_blocks | awk -F":" '{print NF-1}'`
        if [[ x"$num_dots" == "x1" ]]
        then
            #first block
            block_num="0"
            first_blocks_cut=`echo $first_blocks`
        else
            #2+ block
            block_num=`echo $first_blocks | awk -F':' '{print $NF}'`
            block_num="${block_num:0:1}"
            first_blocks_cut=`echo $first_blocks | awk -F':' '{print $1":"$2}'`
        fi
        a=${block_num}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        e=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        f=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
        echo $first_blocks_cut:$a:$b:$c:$d:$e:$f >> /root/ip.list
    else
        echo $first_blocks:$a:$b:$c:$d >> /root/ip.list
    fi
}
while [ "$count" -le $MAXCOUNT ]
do
        rnd_ip_block
        let "count += 1"
done
echo "Generation of a 3proxy config"
mkdir -p /root/3proxy
rm /root/3proxy/3proxy.cfg
cat >/root/3proxy/3proxy.cfg <<EOL
#!/bin/bash

daemon
maxconn 10000
nserver 127.0.0.1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
stacksize 6000
flush
auth strong
users ${proxy_login}:CL:${proxy_pass}
allow ${proxy_login}
EOL

echo >> /root/3proxy/3proxy.cfg
ip4_addr=`ip -4 addr sh dev eth0|grep inet |awk '{print $2}'`
port=${proxy_port}
count=1
for i in `cat /root/ip.list`; do
    echo "proxy -6 -s0 -n -a -p$port -i$ip4_addr -e$i" >> /root/3proxy/3proxy.cfg
    ((port+=1))
    ((count+=1))
done

if grep -q "net.ipv6.ip_nonlocal_bind=1" /etc/sysctl.conf;
then
   echo "All parameters in sysctl have already been set"
else
   echo "Sysctl configuration"
   echo "net.ipv6.conf.eth0.proxy_ndp=1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.all.proxy_ndp=1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
   echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
   echo "net.ipv6.ip_nonlocal_bind=1" >> /etc/sysctl.conf
   echo "vm.max_map_count=95120" >> /etc/sysctl.conf
   echo "kernel.pid_max=95120" >> /etc/sysctl.conf
   echo "net.ipv4.ip_local_port_range=1024 65000" >> /etc/sysctl.conf
   sysctl -p
fi

echo "Configuring rc.local"
rm /etc/rc.local

if [ "$mask" = "64" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net}2 peer ${base_net}1 dev eth0" >> /etc/rc.local
echo "sleep 5" >> /etc/rc.local
echo "ip -6 route add default via ${base_net}1 dev eth0" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo "/root/3proxy/bin/3proxy /root/3proxy/3proxy.cfg" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

if [ "$mask" = "48" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net}2 peer ${base_net}1 dev eth0" >> /etc/rc.local
echo "sleep 5" >> /etc/rc.local
echo "ip -6 route add default via ${base_net}1 dev eth0" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo "/root/3proxy/bin/3proxy /root/3proxy/3proxy.cfg" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

if [ "$mask" = "36" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net1}2/64 dev eth0" >> /etc/rc.local
echo "ip -6 route add default via ${base_net1}1" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo "/root/3proxy/bin/3proxy /root/3proxy/3proxy.cfg" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

if [ "$mask" = "32" ]; then
echo -e '#!/bin/bash \n'  >> /etc/rc.local
echo "ulimit -n 600000" >> /etc/rc.local
echo "ulimit -u 600000" >> /etc/rc.local
echo "ulimit -i 20000" >> /etc/rc.local
echo "ip -6 addr add ${base_net1}2/64 dev eth0" >> /etc/rc.local
echo "ip -6 route add default via ${base_net1}1" >> /etc/rc.local
echo "ip -6 route add local ${base_net}/${mask} dev lo" >> /etc/rc.local
echo "/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf" >> /etc/rc.local
echo "/root/3proxy/bin/3proxy /root/3proxy/3proxy.cfg" >> /etc/rc.local
echo -e "\nexit 0\n" >> /etc/rc.local
/bin/chmod +x /etc/rc.local
fi

echo -en "\033[37;1;41m Configuration complete, restart required \033[0m"
exit 0

