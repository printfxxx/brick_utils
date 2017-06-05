#/bin/sh

dev=eth0

sb_cli detach $dev
sb_cli pool_sz all $dev 0
for cpu in {0..3}; do
	sb_cli pool_sz $cpu $dev 16
	sb_cli qlen $cpu $dev 1024
	sb_cli ps_limit $cpu $dev 0
	sb_cli add_skb $cpu $dev 60 eth+ipv4 mac.dst=0xffffffffffff ipv4.src=0xc0a80a01 ipv4.dst=0xc0a80a02:16
done
sb_cli attach $dev
