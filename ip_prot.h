/* $Id$ */
/* ex: set ts=2 et: */
/**
 * 
 */

/*	*/
static const struct ip_prot {
	unsigned id;
	char name[16],
	desc[32],
	ref[16];
} IP_Prot[] = {
  { 0,	"HOPOPT", "IPv6 Hop-by-Hop Option",           "[RFC1883]" },
	{ 1,	"ICMP", 	"Internet Control Message",         "[RFC792]" },
	{ 2,	"IGMP",   "Internet Group Management",       	"[RFC1112]" },
	{ 3,	"GGP",    "Gateway-to-Gateway",               "[RFC823]" },
	{ 4,	"IP",     "IP in IP (encapsulation)",         "[RFC2003]" },
	{ 5,	"ST",           "Stream",                           "[RFC1190,RFC1819]" },
	{ 6,	"TCP",          "Transmission Control",             "[RFC793]" },
	{ 7,	"CBT",          "CBT",                              "[Ballardie]" },
	{ 8,	"EGP",          "Exterior Gateway Protocol",        "[RFC888,DLM1]" },
	{ 9,	"IGP",          "any private interior gateway (used, by Cisco for their IGRP)", "[IANA]" },
	{ 10,	"BBN-RCC-MON",  "BBN RCC Monitoring",               "[SGC]" },
	{ 11,	"NVP-II",       "Network Voice Protocol",           "[RFC741,SC3]" },
	{ 12,	"PUP",          "PUP",                              "[PUP,XEROX]" },
	{ 13,	"ARGUS",        "ARGUS",                            "[RWS4]" },
	{ 14,	"EMCON",        "EMCON",                            "[BN7]" },
	{ 15,	"XNET",         "Cross Net Debugger",               "[IEN158,JFH2]" },
	{ 16,	"CHAOS",        "Chaos",                            "[NC3]" },
	{ 17,	"UDP",          "User Datagram",                    "[RFC768,JBP]" },
	{ 18,	"MUX",          "Multiplexing",                     "[IEN90,JBP]" },
	{ 19,	"DCN-MEAS",     "DCN Measurement Subsystems",       "[DLM1]" },
	{ 20,	"HMP",          "Host Monitoring",                  "[RFC869,RH6]" },
	{ 21,	"PRM",          "Packet Radio Measurement",             "[ZSU]" },
	{ 22,	"XNS-IDP",      "XEROX NS IDP",                         "[ETHERNET,XEROX]" },
	{ 23,	"TRUNK-1",      "Trunk-1",                              "[BWB6]" },
	{ 24,	"TRUNK-2",      "Trunk-2",                              "[BWB6]" },
	{ 25,	"LEAF-1",       "Leaf-1",                               "[BWB6]" },
	{ 26,	"LEAF-2",       "Leaf-2",                               "[BWB6]" },
	{ 27,	"RDP",          "Reliable Data Protocol",               "[RFC908,RH6]" },
	{ 28,	"IRTP",         "Internet Reliable Transaction",        "[RFC938,TXM]" },
	{ 29,	"ISO-TP4",      "ISO Transport Protocol Class 4",       "[RFC905,RC77]" },
	{ 30, "NETBLT",       "Bulk Data Transfer Protocol",          "[RFC969,DDC1]" },
	{ 31, "MFE-NSP",      "MFE Network Services Protocol",        "[MFENET,BCH2]" },
	{ 32, "MERIT-INP",    "MERIT Internodal Protocol",            "[HWB]" },
	{ 33, "DCCP",         "Datagram Congestion Control Protocol", "[RFC-ietf-dccp-spec-11.txt]" },
	{ 34, "3PC",          "Third Party Connect Protocol",         "[SAF3]" },
	{ 35, "IDPR",         "Inter-Domain Policy Routing Protocol", "[MXS1] " },
	{ 36, "XTP",          "XTP",                                  "[GXC]" },
	{ 37, "DDP", "Datagram Delivery Protocol", "[WXC]" },
	{ 38, "IDPR-CMTP", "IDPR Control Message Transport Proto [MXS1]" },
	{ 39, "TP++", "TP++ Transport Protocol", "[DXF]" },
	{ 40, "IL", "IL Transport Protocol", "[Presotto]" },
	{ 41, "IPv6", "Ipv6", "[Deering]", " },
	{ 42, "SDRP", "Source Demand Routing Protocol", "[DXE1]" },
	{ 43, "IPv6-Route", "Routing Header for IPv6", "[Deering]" },
	{ 44, "IPv6-Frag", "Fragment Header for IPv6", "[Deering]" },
	{ 45, "IDRP", "Inter-Domain Routing Protocol", "[Sue Hares]" },
	{ 46, "RSVP", "Reservation Protocol", "[Bob Braden]" },
	{ 47, "GRE", "General Routing Encapsulation", "[Tony Li]" },
	{ 48, "DSR", "Dynamic Source Routing Protocol", "[RFC-ietf-manet-dsr-10.txt]" },
	{ 49, "BNA", "BNA", "[Gary Salamon]" },
	{ 50, "ESP", "Encap Security Payload", "[RFC2406]" },
	{ 51, "AH", "Authentication Header", "[RFC2402]" },
	{ 52, "I-NLSP", "Integrated Net Layer Security", "TUBA [GLENN]" },
	{ 53, "SWIPE", "IP with Encryption", "[JI6]" },
	{ 54, "NARP", "NBMA Address Resolution Protocol", "[RFC1735]" },
	{ 55, "MOBILE", "IP Mobility", "[Perkins]" },
	{ 56, "TLSP", "Transport Layer Security Protocol", "(using Kryptonet key management[Oberg]" },
	{ 57, "SKIP", "SKIP", "[Markson]" },
	{ 58, "IPv6-ICMP", "ICMP for IPv6", "[RFC1883]" },
	{ 59, "IPv6-NoNxt", "No Next Header for IPv6", "[RFC1883]" },
	{ 60, "IPv6-Opts", "Destination Options for IPv6", "[RFC1883]" },
	{ 61, "any host internal protocol", "[IANA]" },
	{ 62, "CFTP", "CFTP", "[CFTP,HCF2]" },
	{ 63, "any local network", "[IANA]" },
	{ 64, "SAT-EXPAK", "SATNET and Backroom EXPAK", "[SHB]" },
	{ 65, "KRYPTOLAN", "Kryptolan", "[PXL1]" },
	{ 66, "RVD", "MIT Remote Virtual Disk Protocol", "[MBG]" },
	{ 67, "IPPC", "Internet Pluribus Packet Core", "[SHB]" },
	{ 68, "any distributed file system", "[IANA]" },
	{ 69, "SAT-MON", "SATNET Monitoring", "[SHB]" },
	{ 70, "VISA", "VISA Protocol", "[GXT1]" },
	{ 71, "IPCV", "Internet Packet Core Utility", "[SHB]" },
	{ 72, "CPNX", "Computer Protocol Network Executive", "[DXM2]" },
	{ 73, "CPHB", "Computer Protocol Heart Beat", "[DXM2]" },
	{ 74, "WSN", "Wang Span Network", "[VXD]" },
	{ 75, "PVP", "Packet Video Protocol", "[SC3]" },
	{ 76, "BR-SAT-MON", "Backroom SATNET Monitoring", "[SHB]" },
	{ 77, "SUN-ND", "SUN ND PROTOCOL-Temporary", "[WM3]" },
	{ 78, "WB-MON", "WIDEBAND Monitoring", "[SHB]" },
	{ 79, "WB-EXPAK", "WIDEBAND EXPAK", "[SHB]" },
	{ 80, "ISO-IP", "ISO Internet Protocol", "[MTR]" },
	{ 81,	"VMTP	VMTP	[DRC3]" },
	{ 82,	"SECURE-VMTP SECURE-VMTP	[DRC3]" },
	{ 83,	"VINES	VINES	[BXH]" },
	{ 84,	"TTP	TTP	[JXS]" },
	{ 85,	"NSFNET-IGP	NSFNET-IGP	[HWB]" },
	{ 86,	"DGP	Dissimilar Gateway Protocol	[DGP,ML109]" },
	{ 87,	"TCF	TCF	[GAL5]" },
	{ 88,	"EIGRP	EIGRP	[CISCO,GXS]" },
	{ 89,	"OSPFIGP	OSPFIGP	[RFC1583,JTM4]" },
	{ 90,	"Sprite-RPC	Sprite RPC Protocol	[SPRITE,BXW] " },
	{ 91,	"LARP	Locus Address Resolution Protocol	[BXH]" },
	{ 92,	"MTP	Multicast Transport Protocol	[SXA]" },
	{ 93,	"AX.25	AX.25 Frames	[BK29]	" },
	{ 94,	"IPIP	IP-within-IP Encapsulation Protocol	[JI6]" },
	{ 95,	"MICP	Mobile Internetworking Control Pro.	[JI6]" },
	{ 96,	"SCC-SP	Semaphore Communications Sec. Pro.	[HXH]	" },
	{ 97,	"ETHERIP	Ethernet-within-IP Encapsulation	[RFC3378]" },
	{ 98,	"ENCAP	Encapsulation Header	[RFC1241,RXB3]" },
	{ 99,	"any private encryption scheme	[IANA]" },
	{ 100,	"GMTP	GMTP	[RXB5]" },
	{ 101,	"IFMP	Ipsilon Flow Management Protocol	[Hinden]" },
	{ 102,	"PNNI	PNNI over IP	[Callon]" },
	{ 103,	"PIM	Protocol Independent Multicast	[Farinacci]" },
	{ 104,	"ARIS	ARIS	[Feldman]" },
	{ 105,	"SCPS	SCPS	[Durst]" },
	{ 106,	"QNX	QNX	[Hunter]" },
	{ 107,	"A/N	Active Networks	[Braden]" },
	{ 108,	"IPComp	IP Payload Compression Protocol	[RFC2393]" },
	{ 109,	"SNP	Sitara Networks Protocol	[Sridhar]" },
	{ 110,	"Compaq-Peer Compaq Peer Protocol	[Volpe]" },
	{ 111,	"IPX-in-IP	IPX in IP	[Lee]" },
	{ 112,	"VRRP	Virtual Router Redundancy Protocol [RFC3768]" },
	{ 113,	"PGM	PGM Reliable Transport Protocol	[Speakman]" },
	{ 114,	"any 0-hop protocol	[IANA]" },
	{ 115,	"L2TP	Layer Two Tunneling Protocol	[Aboba]" },
	{ 116,	"DDX	D-II Data Exchange (DDX)	[Worley] " },
	{ 117,	"IATP	Interactive Agent Transfer Protocol	[Murphy]" },
	{ 118,	"STP	Schedule Transfer Protocol	[JMP]" },
	{ 119,	"SRP	SpectraLink Radio Protocol	[Hamilton]	" },
	{ 120,	"UTI	UTI	[Lothberg]	" },
	{ 121,	"SMP	Simple Message Protocol	[Ekblad]" },
	{ 122,	"SM	SM	[Crowcroft]" },
	{ 123,	"PTP	Performance Transparency Protocol	[Welzl]" },
	{ 124,	"ISIS over IPv4	[Przygienda]" },
	{ 125,	"FIRE	[Partridge]" },
	{ 126,	"CRTP	Combat Radio Transport Protocol	[Sautter]" },
	{ 127,	"CRUDP	Combat Radio User Datagram	[Sautter]" },
	{ 128,	"SSCOPMCE	[Waber]" },
	{ 129,	"IPLT	[Hollbach]" },
	{ 130,	"SPS	Secure Packet Shield	[McIntosh] " },
	{ 131,	"PIPE	Private IP Encapsulation within IP	[Petri]" },
	{ 132,	"SCTP	Stream Control Transmission Protocol	[Stewart]" },
	{ 133,	"FC	Fibre Channel	[Rajagopal]" },
	{ 134,	"RSVP-E2E-IGNORE	[RFC3175]" },
	{ 135,	"Mobility Header	[RFC3775]" },
	{ 136,	"UDPLite	[RFC3828]" },
	{ 137,	"MPLS-in-IP	[RFC4023]" },
	{ 138,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 139,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 140,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 141,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 142,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 143,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 144,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 145,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 146,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 147,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 148,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 149,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 150,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 151,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 152,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 153,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 154,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 155,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 156,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 157,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 158,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 159,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 160,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 161,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 162,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 163,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 164,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 165,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 166,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 167,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 168,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 169,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 170,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 171,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 172,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 173,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 174,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 175,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 176,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 177,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 178,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 179,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 180,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 181,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 182,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 183,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 184,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 185,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 186,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 187,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 188,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 189,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 190,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 191,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 192,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 193,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 194,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 195,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 196,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 197,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 198,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 199,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 200,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 201,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 202,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 203,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 204,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 205,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 206,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 207,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 208,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 209,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 210,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 211,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 212,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 213,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 214,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 215,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 216,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 217,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 218,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 219,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 220,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 221,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 222,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 223,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 224,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 225,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 226,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 227,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 228,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 229,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 230,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 231,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 232,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 233,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 234,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 235,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 236,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 237,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 238,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 239,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 240,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 241,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 242,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 243,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 244,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 245,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 246,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 247,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 248,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 249,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 250,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 251,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 252,  "Unassigned",   "Unassigned",                       "[IANA]" },
	{ 253,	"Experimental", "Use for experimentation and testing",	"[RFC3692]" },
	{ 254,	"Experimental", "Use for experimentation and testing",	"[RFC3692]" },
	{ 255,	"Reserved",     "Reserved",                         "[IANA]" },
};,
