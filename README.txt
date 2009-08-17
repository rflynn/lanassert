# $Id$
# ex: set ts=2 et:

Installation
=============================================================================

make
sudo make install


Manual
=============================================================================

In order to use LANassert you need a config file which contains rules.


Syntax
-----------------------------------------------------------------------------

Data:

  Scalar Data:
    IP Address:
      Pattern:
        octet.octet.octet.octet[/mask]
      Examples:
        10.0.0.0/8
        192.168.0.0/16
        127.0.0.1
    Ethernet MAC Address:
      Pattern:
        hex:hex:hex:hex:hex:hex
      Examples:
        00:11:22:33:44:55
        de:ad:be:ee:ee:ef
        ff:ff:ff:ff:ff:ff
  List Data:
    [ scalar scalar ]

Argument syntax:

  [fieldname] [operator] [data]

  Examples:

    ETH.SRC IN [ ff:ff:ff:ff:ff:ff ]
    OR (
      ETH.SRC IS 00:11:22:33:44:55
      AND ETH.DST IS AA:BB:CC:DD:EE:FF
    )
    IP.SRC NOT IN [ 10.0.0.0/8 192.168.0.0/16 ]

Operators:

  IS
  	ETH.SRC IS 00:11:22:33:44:55
  !=
  	ETH.SRC != 00:11:22:33:44:55
  IN
  	IP.DST IN [ 192.168.0.0/16 255.255.255.255 ]
  <
  	ICMP.LEN < 56
  >
  	UDP.LEN > 8
  <=
  >=

  Any operator may also be negated with NOT:

  NOT IN
  NOT GT

  etc.

For a list of protocols, msgtype and field names and their datatypes, see
  LANassert -h ref 

Rule Syntax:

  RULE "name"
    [DISABLED]          optionally disable current rule
    MATCH
      [message type]      can be a protocol name like ETH or IP; 
                  some protocols support NAME:TYPE message
                  types, such as ARP:REQ or DNS:RESP.
                  see LANassert -h ref
      [argument]
    ASSERT
      [argument]
    ;

  Examples:

    RULE "Detect any ethernet traffic from unexpected vendor NICs"
      MATCH ETH
      ASSERT ETH.VENDID NOT IN [ 0x001122 0x112233 ]
      ;

    RULE "Detect externally-bound IP traffic"
      # Trivial example, will still pick up multicast, lost DHCP
      # clients, etc.
      MATCH IP
      ASSERT IP.DST IN [ 10.0.0.0/8 172.0.0.0/8 192.168.0.0/16 ]
      ;

    RULE "Detect any attempts to override important server's ARP"
      MATCH
        ARP:RESP
          ARP.SRC.IP IS 192.168.1.1
      ASSERT
        ARP.SRC.MAC IS 00:11:22:33:44:55
      ;

    RULE "Only 192.168.1.1 may serve DNS"
      MATCH DNS:RESP
      ASSERT IP.SRC IS 192.168.1.1
      ;

    RULE "Detect misconfigured DNS clients"
      MATCH DNS:REQ
      ASSERT IP.DST IS 192.168.1.1
      ;



