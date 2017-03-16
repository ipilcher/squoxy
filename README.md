#squoxy

<p align="center">
Copyright 2017 Ian Pilcher
<arequipeno@gmail.com>
</p>

##What Is This?

Network media players, such as Squeezebox and UE Radio, were created with the assumption that they would operate in residential environments with simple, flat networks.  These media players discover local media servers by sending broadcast packets to a particular UDP port; the servers listen for these discovery packets and send unicast responses.

By definition, routers do not forward broadcast traffic, so a Squeezebox or UE Radio media player cannot "see" a server that is not on its local network.

[](https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol) SSDP (the Simple Service Discovery Protocol used by UPnP and DLNA media players) uses multicast packets, rather than broadcast, for initial discovery.  It is possible to route multicast packets, but setting up multicast routing is a non-trivial endeavor, and "doing it right" is almost certainly overkill if one only wants to listen to a few songs.

The good news is that both the players and media servers works perfectly well across a router, as long as the discovery packet makes it to the server somehow.  **squoxy** is a simple program that listens for media player "discovery" packets on one network and forwards those packets to a different network.

##Building squoxy

After cloning this repo ...
~~~
$ cd squoxy
$ gcc -O3 -Wall -Wextra -o squoxy squoxy.c
~~~
If running on an SELinux-enabled system ...
~~~
$ make -f /usr/share/selinux/devel/Makefile
Compiling targeted squoxy module
/usr/bin/checkmodule:  loading policy configuration from tmp/squoxy.tmp
/usr/bin/checkmodule:  policy configuration loaded
/usr/bin/checkmodule:  writing binary representation (version 17) to tmp/squoxy.mod
Creating targeted squoxy.pp policy package
rm tmp/squoxy.mod tmp/squoxy.mod.fc
~~~
##Installing and running

These instructions are written for CentOS 7.  Other recent, systemd-based, distributions should be similar.

Install the SELinux policy module ...
~~~
$ sudo semodule -i squoxy.pp
libsemanage.add_user: user admin not in password file
~~~
(I have no idea what the message about the admin user means; it doesn't seem to affect anything.)

Install the binary ...
~~~
$ sudo cp squoxy /usr/local/bin/
$ sudo restorecon /usr/local/bin/squoxy
~~~
Add the `CAP_NET_RAW` capability, so **squoxy** can create raw sockets as a non-root user ...
~~~
$ sudo setcap cap_net_raw+ep /usr/local/bin/squoxy
~~~
Edit the systemd unit file (`squoxy.service`).  Replace `bond0.253 bond0.248` with the interfaces on which **squoxy** should listen and send.  If desired, the logging verbosity can be changed from **INFO** (`-i`) to **DEBUG** (`-d`) or **NOTIFY** (default).

Install the systemd unit file ...
~~~
$ sudo cp squoxy.service /etc/systemd/system/
$ sudo systemctl daemon-reload
~~~
Start and enable the service ...
~~~
$ sudo systemctl start squoxy
$ sudo systemctl enable squoxy
Created symlink from /etc/systemd/system/multi-user.target.wants/squoxy.service to /etc/systemd/system/squoxy.service.
$ sudo systemctl status squoxy
● squoxy.service - Squeezebox/UE/SSDP discovery forwarder
   Loaded: loaded (/etc/systemd/system/squoxy.service; enabled; vendor preset: disabled)
   Active: active (running) since Wed 2017-03-15 18:06:10 CDT; 11s ago
 Main PID: 1245 (squoxy)
   CGroup: /system.slice/squoxy.service
           └─1245 /usr/local/bin/squoxy -i bond0.253 bond0.248

Mar 15 18:06:10 asterisk.penurio.us systemd[1]: Started Squeezebox/UE/SSDP discovery forwarder.
Mar 15 18:06:10 asterisk.penurio.us systemd[1]: Starting Squeezebox/UE/SSDP discovery forwarder...
Mar 15 18:06:10 asterisk.penurio.us squoxy[1245]: NOTICE: squoxy.c:678: Forwarding from bond0.253 to bond0.248
~~~
##Notes

####Command-line options

**squoxy**'s command-line parsing is quite primitive.  In particular, it generally assumes that the last two arguments are the names of the listen and send network interfaces.  This means that a command like `squoxy -f -h` will silently fail (because `-f` and `-h` are assumed to be network interface names, and error messages are sent to system log by default).

As a special case, `squoxy -h` will display the help message.

| Option | Meaning |
|---|---|
| `-h` | Show the help message and exit successfully.  (The message is always printed to `stdout`.) |
| `-f` | Log to `stderr` rather than the system log. |
| `-d` | Set the logging verbosity to **DEBUG** (conflicts with `-i`). |
| `-i` | Set the logging verbosity to **INFO** (conflicts with `-d`). |
| `-L` | Forward packets that do not include a UDP checksum.  (Normally such packets are ignored.) |

####Logging verbosity

**squoxy**'s default verbosity is **NOTICE**, which is very quiet.  (In fact the only **NOTICE**-level message is currently the startup message.)  Any packets that are dropped because they are malformed will be logged at the **WARNING** level (since they may indicate malicious activity).

Packets that are ignored (dropped) for other reasons — broadcast packets to another UDP port, fragmented packets, etc. — are logged at the **INFO** level.

All packets that are forwarded are logged at the **DEBUG** level.

####IPv6

**squoxy** only supports IPv4.  Until IPv6-only home networks are popular, it seems unlikely that media players and servers will support IPv6 at all, let alone supporting **only** IPv6.

####iptables

The raw sockets used by **squoxy** to listen for discovery packets are affected by **iptables** rules.  (Since the broadcast listener socket listens for broadcast traffic on **all** UDP ports, this is a good thing.)

Example rules to allow Squeezebox (`255.255.255.255:3483`), UE Radio (`255.255.255.255:3546`) and SSDP (`239.255.255.250:1900`) discovery packets:

~~~
# iptables -A INPUT -d 255.255.255.255/32 -p udp --dport 3483 -j ACCEPT
# iptables -A INPUT -d 255.255.255.255/32 -p udp --dport 3546 -j ACCEPT
# iptables -A INPUT -d 239.255.255.250/32 -p udp --dport 1900 -j ACCEPT
~~~
In the real world, these should probably be restricted by source IP address or input interface.
