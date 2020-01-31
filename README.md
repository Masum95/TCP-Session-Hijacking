# TCP-Session-Hijacking
In this attack we will try to sniff an ongoing tcp session and hijack thereby. In addition to just hijacking a session, we demonstrate how to create a **reverse-shell** on attacker machine which eventually enables us to incur pretty much every possible damage on victim. 
Before performing actual attack, we need to setup virtual network. We use mininet for this purpose.
We create a virtual network with 3 hosts. Mininet command for this:

>sudo mn -x --topo=single,3

Now, to perform session hijacking attacker needs to sniff the ongoing packets between host 1 and host 2.
To do this, we will send arp-spoofed packet from host 3. Command for this one is :
>arpspoof -i h3-eth0 -t 10.0.0.1 -r 10.0.0.2 > /dev/null 2>&1 &

>arpspoof -i h3-eth0 -t 10.0.0.2 -r 10.0.0.1 > /dev/null 2>&1 &


Now run the "run.sh"

To know more about the theoretical and practical aspects of the attack,  go through the **Tcp_session_hijacking.pdf** on the repo. Sequential steps to create **reverse-shell** on attacker machine are described there.(with **screenshots**) 
