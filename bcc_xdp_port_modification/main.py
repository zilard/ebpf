#!/usr/bin/env python3

"""
I picked the simple problem of changing the dest port on UDP packets from 7999 to 7998.


Open three terminals and run the following two commands in two of them:

nc -kul 127.0.0.1 7999


nc -kul 127.0.0.1 7998


These terminals are our listening processes. We are using nc netcat to open up a socket listening to udp packets that come in to the 127.0.0.1 address on ports 7999 and 7998. The -k argument simply tells netcat to continue listening after it has received a packet so it can receive more packets from other clients.

In our third terminal, run:

nc -u 127.0.0.1 7999


Then on the next line, type some text followed by <Enter>. You should see the text echoed in the first terminal, listening on port 7999. Once we put our XDP application in place, attached to the lo loopback device, the packet will be modified en route and diverted to the other terminal listening on port 7998.
"""

from bcc import BPF
import time

device = "lo"


# we create our BPF program based on the source file filter.c
# invokes the BPF compiler and verifier to make sure the BPF program is valid and safe to run.

b = BPF(src_file="filter.c")



# we specify the function from our BPF program that we want to use as a callback
# to handle incoming packets and designate it as an XDP program type.

fn = b.load_func("udpfilter", BPF.XDP)


# we attach our XDP function to the device we specified above
# Once our XDP function is attached to the network interface, it will begin processing packets.

b.attach_xdp(device, fn, 0)

# we put our loader into a wait loop that watches for any printed messages 
# from our BPF application and prints them to the screen.
# This will run indefinitely, so we wrap it in a try/except block to catch 
# a Ctrl-C and allow the program to proceed.

try:
  b.trace_print()
except KeyboardInterrupt:
  pass


# with the user having indicated the program should exit, 
# we remove our XDP application from the network interface.

b.remove_xdp(device, 0)

