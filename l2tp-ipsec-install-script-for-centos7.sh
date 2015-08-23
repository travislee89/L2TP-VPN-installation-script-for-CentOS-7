#!/bin/bash
####################################################
#                                                  #
# This is a L2TP VPN installation for CentOS 7     #
# Version: 1.1.0 20140803                          #
# Author: Travis Lee                               #
# Website: http://www.stunnel.info                 #
#                                                  #
####################################################

#检测是否是root用户
if [[ $(id -u) != "0" ]]; then
    printf "\e[42m\e[31mError: You must be root to run this install script.\e[0m\n"
    exit 1
fi

#检测是否是CentOS 7或者RHEL 7
if [[ $(grep "release 7." /etc/redhat-release 2>/dev/null | wc -l) -eq 0 ]]; then
    printf "\e[42m\e[31mError: Your OS is NOT CentOS 7 or RHEL 7.\e[0m\n"
    printf "\e[42m\e[31mThis install script is ONLY for CentOS 7 and RHEL 7.\e[0m\n"
    exit 1
fi
clear

printf "
####################################################
#                                                  #
# This is a L2TP VPN installation for CentOS 7     #
# Version: 1.1.0 20140803                          #
# Author: Travis Lee                               #
# Website: http://www.stunnel.info                 #
#                                                  #
####################################################
"

#获取服务器IP
serverip=$(ifconfig -a |grep -w "inet"| grep -v "127.0.0.1" |awk '{print $2;}')
printf "\e[33m$serverip\e[0m is the server IP?"
printf "If \e[33m$serverip\e[0m is \e[33mcorrect\e[0m, press enter directly."
printf "If \e[33m$serverip\e[0m is \e[33mincorrect\e[0m, please input your server IP."
printf "(Default server IP: \e[33m$serverip\e[0m):"
read serveriptmp
if [[ -n "$serveriptmp" ]]; then
    serverip=$serveriptmp
fi

#获取网卡接口名称
ethlist=$(ifconfig | grep ": flags" | cut -d ":" -f1)
eth=$(printf "$ethlist\n" | head -n 1)
if [[ $(printf "$ethlist\n" | wc -l) -gt 2 ]]; then
    echo ======================================
    echo "Network Interface list:"
    printf "\e[33m$ethlist\e[0m\n"
    echo ======================================
    echo "Which network interface you want to listen for ocserv?"
    printf "Default network interface is \e[33m$eth\e[0m, let it blank to use default network interface: "
    read ethtmp
    if [ -n "$ethtmp" ]; then
        eth=$ethtmp
    fi
fi

#设置VPN拨号后分配的IP段
iprange="10.0.1"
echo "Please input IP-Range:"
printf "(Default IP-Range: \e[33m$iprange\e[0m): "
read iprangetmp
if [[ -n "$iprangetmp" ]]; then
    iprange=$iprangetmp
fi

#设置预共享密钥
mypsk="stunnel.info"
echo "Please input PSK:"
printf "(Default PSK: \e[33mstunnel.info\e[0m): "
read mypsktmp
if [[ -n "$mypsktmp" ]]; then
    mypsk=$mypsktmp
fi

#设置VPN用户名
username="stunnel"
echo "Please input VPN username:"
printf "(Default VPN username: \e[33mstunnel\e[0m): "
read usernametmp
if [[ -n "$usernametmp" ]]; then
    username=$usernametmp
fi

#随机密码
randstr() {
    index=0
    str=""
    for i in {a..z}; do arr[index]=$i; index=$(expr ${index} + 1); done
    for i in {A..Z}; do arr[index]=$i; index=$(expr ${index} + 1); done
    for i in {0..9}; do arr[index]=$i; index=$(expr ${index} + 1); done
    for i in {1..10}; do str="$str${arr[$RANDOM%$index]}"; done
    echo $str
}

#设置VPN用户密码
password=$(randstr)
printf "Please input \e[33m$username\e[0m's password:\n"
printf "Default password is \e[33m$password\e[0m, let it blank to use default password: "
read passwordtmp
if [[ -n "$passwordtmp" ]]; then
    password=$passwordtmp
fi

clear

#打印配置参数
clear
echo "Server IP:"
echo "$serverip"
echo
echo "Server Local IP:"
echo "$iprange.1"
echo
echo "Client Remote IP Range:"
echo "$iprange.10-$iprange.254"
echo
echo "PSK:"
echo "$mypsk"
echo
echo "Press any key to start..."

get_char() {
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}
char=$(get_char)
clear
mknod /dev/random c 1 9

#安装依赖的组件
yum -y update
yum install -y openswan ppp xl2tpd wget

rm -f /etc/ipsec.conf
#创建ipsec.conf配置文件
cat >>/etc/ipsec.conf<<EOF
# /etc/ipsec.conf - Libreswan IPsec configuration file

# This file:  /etc/ipsec.conf
#
# Enable when using this configuration file with openswan instead of libreswan
#version 2
#
# Manual:     ipsec.conf.5

# basic configuration
config setup
    # NAT-TRAVERSAL support, see README.NAT-Traversal
    nat_traversal=yes
    # exclude networks used on server side by adding %v4:!a.b.c.0/24
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12
    # OE is now off by default. Uncomment and change to on, to enable.
    oe=off
    # which IPsec stack to use. auto will try netkey, then klips then mast
    protostack=netkey
    force_keepalive=yes
    keep_alive=1800

conn L2TP-PSK-NAT
    rightsubnet=vhost:%priv
    also=L2TP-PSK-noNAT

conn L2TP-PSK-noNAT
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=$serverip
    leftid=$serverip
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    dpddelay=40
    dpdtimeout=130
    dpdaction=clear
# For example connections, see your distribution's documentation directory,
# or the documentation which could be located at
#  /usr/share/docs/libreswan-3.*/ or look at https://www.libreswan.org/
#
# There is also a lot of information in the manual page, "man ipsec.conf"

# You may put your configuration (.conf) file in the "/etc/ipsec.d/" directory
# by uncommenting this line
#include /etc/ipsec.d/*.conf
EOF

#设置预共享密钥配置文件
rm -f /etc/ipsec.secrets
cat >>/etc/ipsec.secrets<<EOF
#include /etc/ipsec.d/*.secrets
$serverip %any: PSK "$mypsk"
EOF

#创建xl2tpd.conf配置文件
mkdir -p /etc/xl2tpd
rm -f /etc/xl2tpd/xl2tpd.conf
cat >>/etc/xl2tpd/xl2tpd.conf<<EOF
;
; This is a minimal sample xl2tpd configuration file for use
; with L2TP over IPsec.
;
; The idea is to provide an L2TP daemon to which remote Windows L2TP/IPsec
; clients connect. In this example, the internal (protected) network
; is 192.168.1.0/24.  A special IP range within this network is reserved
; for the remote clients: 192.168.1.128/25
; (i.e. 192.168.1.128 ... 192.168.1.254)
;
; The listen-addr parameter can be used if you want to bind the L2TP daemon
; to a specific IP address instead of to all interfaces. For instance,
; you could bind it to the interface of the internal LAN (e.g. 192.168.1.98
; in the example below). Yet another IP address (local ip, e.g. 192.168.1.99)
; will be used by xl2tpd as its address on pppX interfaces.
[global]
; ipsec saref = yes
listen-addr = $serverip
auth file = /etc/ppp/chap-secrets
port = 1701
[lns default]
ip range = $iprange.10-$iprange.254
local ip = $iprange.1
refuse chap = yes
refuse pap = yes
require authentication = yes
name = L2TPVPN
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

#创建options.xl2tpd配置文件
mkdir -p /etc/ppp
rm -f /etc/ppp/options.xl2tpd
cat >>/etc/ppp/options.xl2tpd<<EOF
#require-pap
#require-chap
#require-mschap
ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1400
noccp
connect-delay 5000
# To allow authentication against a Windows domain EXAMPLE, and require the
# user to be in a group "VPN Users". Requires the samba-winbind package
# require-mschap-v2
# plugin winbind.so
# ntlm_auth-helper '/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1 --require-membership-of="EXAMPLE\VPN Users"'
# You need to join the domain on the server, for example using samba:
# http://rootmanager.com/ubuntu-ipsec-l2tp-windows-domain-auth/setting-up-openswan-xl2tpd-with-native-windows-clients-lucid.html
EOF

#创建chap-secrets配置文件，即用户列表及密码
rm -f /etc/ppp/chap-secrets
cat >>/etc/ppp/chap-secrets<<EOF
# Secrets for authentication using CHAP
# client     server     secret               IP addresses
$username          l2tpd     $password               *
EOF

#修改系统配置，允许IP转发
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.$eth.rp_filter=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

cat >>/etc/sysctl.conf<<EOF

net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$eth.rp_filter = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF

#允许防火墙端口
cat >/usr/lib/firewalld/services/l2tpd.xml<<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>l2tpd</short>
  <description>L2TP IPSec</description>
  <port protocol="udp" port="500"/>
  <port protocol="udp" port="4500"/>
  <port protocol="udp" port="1701"/>
</service>
EOF

firewall-cmd --permanent --add-service=l2tpd
firewall-cmd --permanent --add-service=ipsec
firewall-cmd --permanent --add-masquerade
firewall-cmd --reload
#iptables --table nat --append POSTROUTING --jump MASQUERADE
#iptables -t nat -A POSTROUTING -s $iprange.0/24 -o $eth -j MASQUERADE
#iptables -t nat -A POSTROUTING -s $iprange.0/24 -j SNAT --to-source $serverip
#service iptables save

#允许开机启动
systemctl enable ipsec xl2tpd
systemctl restart ipsec xl2tpd
clear

#测试ipsec
ipsec verify

printf "
####################################################
#                                                  #
# This is a L2TP VPN installation for CentOS 7     #
# Version: 1.1.0 20140803                          #
# Author: Travis Lee                               #
# Website: http://www.stunnel.info                 #
#                                                  #
####################################################
if there are no [FAILED] above, then you can
connect to your L2TP VPN Server with the default
user/password below:

ServerIP: $serverip
username: $username
password: $password
PSK: $mypsk

"
