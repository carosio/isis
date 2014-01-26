IS-IS implementation
====================

Main components:

isis_system - the root process of an IS-IS system. This holds various
bits of configuration state (such as the system id), along with the
details of any pseudo-nodes allocated. It also holds the set of
interfaces, where each interface is a process that deals with the I/O
on that interface.

isis_interface - A gen_server process that holds all the state for an
interface, including mundane things like the name, MAC/SNPA, MTU and
timers as well as adjacencies formed.

isis_adjacency - A gen_fsm to run the 3-way handshake for an adjacency
over is owning interface.

isis_lspdb - The LSP database. Run as a gen_server, Learnt LSPs are
installed into the ETS table owned by this process. Lookups are done
direct (ie, without using gen_server:call()).