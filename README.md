This problem is particularly important because TCP serves as one of the primary protocols for data transfer over the web today. 
A misbehaving receiver can therefore manipulate the sender to send a large amount of packets to it, possibly harming the connection of other receivers or network users. 
In addition, later related research in [1] describes how a group of misbehaving receivers can be used in tandem to cause congestion collapse and/or execute a distributed denial of service (DDoS) attack against a host.
The paper states, “We first demonstrate that there are simple attacks that allow a misbehaving receiver to drive a standard TCP sender arbitrarily fast, without losing end-to-end reliability. 
These attacks are widely applicable because they stem from the sender behavior specified in RFC 2581 rather than implementation bugs. 
We then show that it is possible to modify TCP to eliminate this undesirable behavior entirely, without requiring assumptions of any kind about receiver behavior.” [
It describes three main attacks that a misbehaving TCP receiver could execute against the sender. Each exploited a slightly different characteristic of the TCP sender specification detailed in RFC 2581 – based on byte level error granularity, duplicate acks, and optimistic acking. After demonstrating the feasibility of the attacks, the authors devised a solution for each attack.

We were able to successfully replicate the optimistic ACK attack, demonstrating that this weakness is still present in TCP today. 
We were also able to implement a defense, confirming that, in theory, TCP stacks can be defended against optimistic ACK attackers. 
However, we feel that, other than the defense for ACK division, none of the proposed defenses are realistic in practice. 
Two of the defenses described in the paper require changes to both receiver and sender via an extra TCP header, which seems impractical to deploy. 
The defense that we implemented only required changes to the sender, but we still feel it shouldn’t be deployed since there may be legitimate reasons for a receiver to not ACK on segment boundaries.

If this paper was written in 1999, and we are still able to successfully perform the optimistic ACK attack, it brings into question whether TCP will ever be defended against this attack.

3 Implementation experience

To exploit the vulnerabilities described above, we made three modifications to the TCP subsystem of Linux 2.2.10. This resulting
TCP implementation, which we refer to facetiously as “TCP Daytona”, provides extremely high performance at the expense of its
competitors. We demonstrate these abilities with time sequence
plots of packet traces for both normal and modified receiver TCP's.
Needless to say, our implementation is intentionally not “stable”,
and would likely

To run the project:

1- You must have python 2.7, mininet 2.2.2, matplotlib 2.2.2 and scapy module.
Run this command in terminal
sudo python main.py 

After running, you will see the newly created log and graphs files.

NOTE: This project is compatible with Ubuntu 14.04. Cannot guarantee other versions. (düzenlendi)
