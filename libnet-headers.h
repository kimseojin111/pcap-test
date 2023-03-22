#include <stdlib.h>

#include <pcap.h>
#include <arpa/inet.h>    //using (ntohs ntohl htons htonl) function
#include <netinet/in.h>   //using (inet_ntoa) function


struct sibal {
    int fuck;
};

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];/* destination ethernet address */
    u_int8_t  ether_shost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};


struct libnet_ipv4_hdr
{
//#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
//#endif
//#if (LIBNET_BIG_ENDIAN)
//    u_int8_t ip_v:4,       /* version */
//           ip_hl:4;        /* header length */
//#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  IP options
 */
#ifndef IPOPT_EOL
#define IPOPT_EOL       0   /* end of option list */
#endif
#ifndef IPOPT_NOP
#define IPOPT_NOP       1   /* no operation */
#endif   
#ifndef IPOPT_RR
#define IPOPT_RR        7   /* record packet route */
#endif
#ifndef IPOPT_TS
#define IPOPT_TS        68  /* timestamp */
#endif
#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   
#endif
#ifndef IPOPT_LSRR
#define IPOPT_LSRR      131 /* loose source route */
#endif
#ifndef IPOPT_SATID
#define IPOPT_SATID     136 /* satnet id */
#endif
#ifndef IPOPT_SSRR
#define IPOPT_SSRR      137 /* strict source route */
#endif

struct libnet_in6_addr
{
    union
    {
        u_int8_t   __u6_addr8[16];
        u_int16_t  __u6_addr16[8];
        u_int32_t  __u6_addr32[4];
    } __u6_addr;            /* 128-bit IP6 address */
};
#define libnet_s6_addr __u6_addr.__u6_addr8

/*
 *  IPv6 header
 *  Internet Protocol, version 6
 *  Static header size: 40 bytes
 */
struct libnet_ipv6_hdr
{
    u_int8_t ip_flags[4];     /* version, traffic class, flow label */
    u_int16_t ip_len;         /* total length */
    u_int8_t ip_nh;           /* next header */
    u_int8_t ip_hl;           /* hop limit */
    struct libnet_in6_addr ip_src, ip_dst; /* source and dest address */

};

/*
 *  IPv6 frag header
 *  Internet Protocol, version 6
 *  Static header size: 8 bytes
 */
#define LIBNET_IPV6_NH_FRAGMENT 44
struct libnet_ipv6_frag_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_reserved;    /* reserved */
    u_int16_t ip_frag;       /* fragmentation stuff */
    u_int32_t ip_id;         /* id */
};

/*
 *  IPv6 routing header
 *  Internet Protocol, version 6
 *  Base header size: 4 bytes
 */
#define LIBNET_IPV6_NH_ROUTING  43
struct libnet_ipv6_routing_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    u_int8_t ip_rtype;       /* routing type */
    u_int8_t ip_segments;    /* segments left */
    /* routing information allocated dynamically */
};

/*
 *  IPv6 destination options header
 *  Internet Protocol, version 6
 *  Base header size: 2 bytes
 */
#define LIBNET_IPV6_NH_DESTOPTS 60
struct libnet_ipv6_destopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};

/*
 *  IPv6 hop by hop options header
 *  Internet Protocol, version 6
 *  Base header size: 2 bytes
 */
#define LIBNET_IPV6_NH_HBH      0
struct libnet_ipv6_hbhopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};

/*
 *  ICMP6 header
 *  Internet Control Message Protocol v6
 *  Base header size: 8 bytes
 */
#ifndef IPPROTO_ICMP6
#define IPPROTO_ICMP6   0x3a
#endif
struct libnet_icmpv6_hdr
{
    u_int8_t icmp_type;       /* ICMP type */
#ifndef ICMP6_ECHO
#define ICMP6_ECHO          128
#endif
#ifndef ICMP6_ECHOREPLY
#define ICMP6_ECHOREPLY     129
#endif
#ifndef ICMP6_UNREACH
#define ICMP6_UNREACH       1
#endif
#ifndef ICMP6_PKTTOOBIG
#define ICMP6_PKTTOOBIG     2
#endif
#ifndef ICMP6_TIMXCEED
#define ICMP6_TIMXCEED      3
#endif
#ifndef ICMP6_PARAMPROB
#define ICMP6_PARAMPROB     4
#endif
    u_int8_t icmp_code;       /* ICMP code */
    u_int16_t icmp_sum;       /* ICMP Checksum */
    u_int16_t id;             /* ICMP id */
    u_int16_t seq;            /* ICMP sequence number */
};



/*
 *  ICMP header
 *  Internet Control Message Protocol
 *  Base header size: 4 bytes
 */

/*
 *  IGMP header
 *  Internet Group Message Protocol
 *  Static header size: 8 bytes
 */
struct libnet_igmp_hdr
{
    u_int8_t igmp_type;       /* IGMP type */
#ifndef IGMP_MEMBERSHIP_QUERY
#define IGMP_MEMBERSHIP_QUERY           0x11    /* membership query */
#endif
#ifndef IGMP_V1_MEMBERSHIP_REPORT
#define IGMP_V1_MEMBERSHIP_REPORT       0x12    /* Ver. 1 membership report */
#endif
#ifndef IGMP_V2_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT       0x16    /* Ver. 2 membership report */
#endif
#ifndef IGMP_LEAVE_GROUP
#define IGMP_LEAVE_GROUP                0x17    /* Leave-group message */
#endif
    u_int8_t igmp_code;       /* IGMP code */
    u_int16_t igmp_sum;       /* IGMP checksum */
    struct in_addr igmp_group;/* IGMP host IP */
};


/*
 *  IPSEC header
 *  Internet Protocol Security Protocol
 *  Encapsulating Security Payload Header Static header size: 12 bytes
 *  Encapsulating Security Payload Footer Base header size: 2 bytes
 *  Authentication Header Static Size: 16 bytes
 */
#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50      /* not everyone's got this */
#endif
struct libnet_esp_hdr
{
   u_int32_t esp_spi;          /* security parameter index */
   u_int32_t esp_seq;          /* ESP sequence number */
   u_int32_t esp_iv;           /* initialization vector */
};

struct libnet_esp_ftr
{
    u_int8_t esp_pad_len;     /* padding length */
    u_int8_t esp_nh;     /* next header pointer */
    int8_t *esp_auth;         /* authentication data */
};
 
#ifndef IPPROTO_AH
#define IPPROTO_AH 51       /* not everyone's got this */
#endif
struct libnet_ah_hdr
{
    u_int8_t ah_nh;      /* next header */
    u_int8_t ah_len;          /* payload length */
    u_int16_t ah_res;         /* reserved */
    u_int32_t ah_spi;          /* security parameter index  */
    u_int32_t ah_seq;          /* AH sequence number */
    u_int32_t ah_auth;         /* authentication data */
};


/*
 *  ISL header
 *  Cisco Inter-Switch Link
 *  Static header size: 26 bytes
 */
/*
 *  For checksum stuff -- IANA says 135-254 is "unassigned" as of 12.2001.
 *  Let's hope this one stays that way for a while!
 */
#define LIBNET_PROTO_ISL    201
struct libnet_isl_hdr
{
    u_int8_t isl_dhost[5];    /* destination address "01:00:0c:00:00" */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t isl_type:4,      /* type of frame */
           isl_user:4;      /* user defined bits */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t isl_user:4,      /* user defined bits */
           isl_type:4;      /* type of frame */
#endif
    u_int8_t isl_shost[6];    /* source address */
    u_int16_t isl_len;        /* total length of packet - 18 bytes */
    u_int8_t isl_snap[6];     /* 0xaaaa03 + vendor code */
    u_int16_t isl_vid;        /* 15 bit VLAN ID, 1 bit BPDU / CDP indicator */
    u_int16_t isl_index;      /* port index */
    u_int16_t isl_reserved;   /* used for FDDI and token ring */
    /* ethernet frame and 4 byte isl crc */
};

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF    89  /* not everyone's got this */
#endif
#define IPPROTO_OSPF_LSA    890     /* made this up.  Hope it's unused */
#define LIBNET_MODX         4102    /* used in LSA checksum */

/*
 *  Options used in multiple OSPF packets
 *  More info can be found in section A.2 of RFC 2328.
 */
#define LIBNET_OPT_EBIT  0x02 /* describes the way AS-external-LSAs are flooded */
#define LIBNET_OPT_MCBIT 0x04 /* whether or not IP multicast dgrams are fwdd */
#define LIBNET_OPT_NPBIT 0x08 /* describes handling of type-7 LSAs */
#define LIBNET_OPT_EABIT 0x10 /* rtr's willingness to send/recv EA-LSAs */
#define LIBNET_OPT_DCBIT 0x20 /* describes handling of demand circuits */


/*
 *  MPLS header
 *  Multi-Protocol Label Switching
 *  Static header size: 4 bytes
 */
struct libnet_mpls_hdr
{
    u_int32_t mpls_les;          /* 20 bits label, 3 bits exp, 1 bit bos, ttl */
#define LIBNET_MPLS_BOS_ON    1
#define LIBNET_MPLS_BOS_OFF   0
};

/*
 *  NTP header
 *  Network Time Protocol
 *  Static header size: 48 bytes
 */
struct libnet_ntp_hdr_l_fp  /* int32_t floating point (64-bit) */
{
    u_int32_t integer;         /* integer */
    u_int32_t fraction;        /* fraction */
};

struct libnet_ntp_hdr_s_fp  /* int16_t floating point (32-bit) */
{
    u_int16_t integer;        /* integer */
    u_int16_t fraction;       /* fraction */
};


struct libnet_ntp_hdr
{
    u_int8_t ntp_li_vn_mode;              /* leap indicator, version, mode */
#define LIBNET_NTP_LI_NW    0x0         /* no warning */
#define LIBNET_NTP_LI_AS    0x1         /* last minute has 61 seconds */
#define LIBNET_NTP_LI_DS    0x2         /* last minute has 59 seconds */
#define LIBNET_NTP_LI_AC    0x3         /* alarm condition */

#define LIBNET_NTP_VN_2     0x2         /* version 2 */
#define LIBNET_NTP_VN_3     0x3         /* version 3 */
#define LIBNET_NTP_VN_4     0x4         /* version 4 */

#define LIBNET_NTP_MODE_R   0x0         /* reserved */
#define LIBNET_NTP_MODE_A   0x1         /* symmetric active */
#define LIBNET_NTP_MODE_P   0x2         /* symmetric passive */
#define LIBNET_NTP_MODE_C   0x3         /* client */
#define LIBNET_NTP_MODE_S   0x4         /* server */
#define LIBNET_NTP_MODE_B   0x5         /* broadcast */
#define LIBNET_NTP_MODE_RC  0x6         /* reserved for NTP control message */
#define LIBNET_NTP_MODE_RP  0x7         /* reserved for private use */
    u_int8_t ntp_stratum;                 /* stratum */
#define LIBNET_NTP_STRATUM_UNAVAIL  0x0 /* unspecified or unavailable */
#define LIBNET_NTP_STRATUM_PRIMARY  0x1 /* primary reference (radio clock) */
                                        /* 2 - 15 is secondary */
                                        /* 16 - 255 is reserved */
    u_int8_t ntp_poll;                    /* poll interval (should be 4 - 12) */
    u_int8_t ntp_precision;               /* local clock precision */
    struct libnet_ntp_hdr_s_fp ntp_delay;       /* roundtrip delay */
    struct libnet_ntp_hdr_s_fp ntp_dispersion;  /* nominal error */
    u_int32_t ntp_reference_id;                /* reference source id */
#define LIBNET_NTP_REF_LOCAL    0x4c4f434c  /* uncalibrated local clock */
#define LIBNET_NTP_REF_PPS      0x50505300  /* atomic / pulse-per-second clock */
#define LIBNET_NTP_REF_ACTS     0x41435453  /* NIST dialup modem */
#define LIBNET_NTP_REF_USNO     0x55534e4f  /* USNO modem service */
#define LIBNET_NTP_REF_PTB      0x50544200  /* PTB (German) modem service */ 
#define LIBNET_NTP_REF_TDF      0x54444600  /* Allouis (French) radio */
#define LIBNET_NTP_REF_DCF      0x44434600  /* Mainflingen (German) radio */
#define LIBNET_NTP_REF_MSF      0x4d534600  /* Rugby (UK) radio */
#define LIBNET_NTP_REF_WWV      0x57575600  /* Ft Collins (US) radio */
#define LIBNET_NTP_REF_WWVB     0x57575642  /* Boulder (US) radio */
#define LIBNET_NTP_REF_WWVH     0x57575648  /* Kaui Hawaii (US) radio */
#define LIBNET_NTP_REF_CHU      0x43485500  /* Ottaha (Canada) radio */
#define LIBNET_NTP_REF_LORC     0x4c4f5243  /* LORAN-C radionavigation */
#define LIBNET_NTP_REF_OMEG     0x4f4d4547  /* OMEGA radionavigation */
#define LIBNET_NTP_REF_GPS      0x47505300  /* global positioning system */
#define LIBNET_NTP_REF_GOES     0x474f4553  /* geostationary orbit env satellite */
    struct libnet_ntp_hdr_l_fp ntp_ref_ts;  /* reference timestamp */ 
    struct libnet_ntp_hdr_l_fp ntp_orig_ts; /* originate timestamp */
    struct libnet_ntp_hdr_l_fp ntp_rec_ts;  /* receive timestamp */
    struct libnet_ntp_hdr_l_fp ntp_xmt_ts;  /* transmit timestamp */
};


/*
 *  OSPFv2 header
 *  Open Shortest Path First
 *  Static header size: 16 bytes
 */
struct libnet_ospf_hdr
{
    u_int8_t ospf_v;          /* version */
#define OSPFVERSION         2
    u_int8_t ospf_type;       /* type */
#define  LIBNET_OSPF_UMD    0   /* UMd monitoring packet */
#define  LIBNET_OSPF_HELLO  1   /* HELLO packet */
#define  LIBNET_OSPF_DBD    2   /* dataBase description packet */
#define  LIBNET_OSPF_LSR    3   /* link state request packet */
#define  LIBNET_OSPF_LSU    4   /* link state Update Packet */
#define  LIBNET_OSPF_LSA    5   /* link state acknowledgement packet */
    u_int16_t   ospf_len;     /* length */
    struct in_addr ospf_rtr_id; /* source router ID */
    struct in_addr ospf_area_id;/* roam ID */
    u_int16_t ospf_sum;         /* checksum */
    u_int16_t ospf_auth_type;     /* authentication type */
#define LIBNET_OSPF_AUTH_NULL   0   /* null password */
#define LIBNET_OSPF_AUTH_SIMPLE 1   /* simple, plaintext, 8 int8_t password */
#define LIBNET_OSPF_AUTH_MD5    2   /* MD5 */
};


/*
 *  OSPF authentication header
 *  Open Shortest Path First
 *  Static header size: 8 bytes
 */
struct libnet_auth_hdr
{
    u_int16_t ospf_auth_null; /* NULL */
    u_int8_t ospf_auth_keyid; /* authentication key ID */
    u_int8_t ospf_auth_len;   /* auth data length */
    u_int ospf_auth_seq;    /* cryptographic sequence number */
};


/*
 *  OSPF hello header
 *  Open Shortest Path First
 *  Static header size: 28 bytes
 */
struct libnet_ospf_hello_hdr
{
    struct in_addr hello_nmask; /* netmask associated with the interface */
    u_int16_t hello_intrvl;       /* num of seconds between routers last packet */
    u_int8_t hello_opts;          /* Options for HELLO packets (look above) */
    u_int8_t hello_rtr_pri;       /* router's priority (if 0, can't be backup) */
    u_int hello_dead_intvl;     /* # of secs a router is silent till deemed down */
    struct in_addr hello_des_rtr;   /* Designated router on the network */
    struct in_addr hello_bkup_rtr;  /* Backup router */
    struct in_addr hello_nbr;       /* neighbor router, memcpy more as needed */
};


/*
 *  Database Description header.
 */
struct libnet_dbd_hdr
{
    u_int16_t dbd_mtu_len;    /* max length of IP dgram that this 'if' can use */
    u_int8_t dbd_opts;        /* DBD packet options (from above) */
    u_int8_t dbd_type;        /* type of exchange occurring */
#define LIBNET_DBD_IBI      0x01    /* init */
#define LIBNET_DBD_MBIT     0x02    /* more DBD packets are to come */
#define LIBNET_DBD_MSBIT    0x04    /* If 1, sender is the master in the exchange */
    u_int  dbd_seq;         /* DBD sequence number */
};


/*
 *  used for the LS type field in all LS* headers
 */
#define LIBNET_LS_TYPE_RTR      1   /* router-LSA */
#define LIBNET_LS_TYPE_NET      2   /* network-LSA */
#define LIBNET_LS_TYPE_IP       3   /* summary-LSA (IP Network) */
#define LIBNET_LS_TYPE_ASBR     4   /* summary-LSA (ASBR) */
#define LIBNET_LS_TYPE_ASEXT    5   /* AS-external-LSA */


/*
 *  Link State Request header
 */
struct libnet_lsr_hdr
{
    u_int lsr_type;             /* type of LS being requested */
    u_int lsr_lsid;             /* link state ID */
    struct in_addr lsr_adrtr;   /* advertising router (memcpy more as needed) */
};


/*
 *  Link State Update header
 */
struct libnet_lsu_hdr
{
    u_int lsu_num;              /* number of LSAs that will be broadcasted */
};


/*
 *  Link State Acknowledgement header.
 */
struct libnet_lsa_hdr
{
    u_int16_t lsa_age;        /* time in seconds since the LSA was originated */
    u_int8_t lsa_opts;        /* look above for OPTS_* */
    u_int8_t lsa_type;        /* look below for LS_TYPE_* */
    u_int lsa_id;           /* link State ID */
    struct in_addr lsa_adv; /* router ID of Advertising router */
    u_int lsa_seq;          /* LSA sequence number to detect old/bad ones */
    u_int16_t lsa_sum;      /* "Fletcher Checksum" of all fields minus age */
    u_int16_t lsa_len;        /* length in bytes including the 20 byte header */
};


/*
 *  Router LSA data format
 *
 *  Other stuff for TOS can be added for backward compatability, for this
 *  version, only OSPFv2 is being FULLY supported.
 */
struct libnet_rtr_lsa_hdr
{
    u_int16_t rtr_flags;      /* set to help describe packet */
#define LIBNET_RTR_FLAGS_W  0x0100  /* W bit */
#define LIBNET_RTR_FLAGS_E  0x0200  /* E bit */
#define LIBNET_RTR_FLAGS_B  0x0400  /* B bit */
    u_int16_t rtr_num;        /* number of links within that packet */
    u_int rtr_link_id;      /* describes link_data (look below) */
#define LIBNET_LINK_ID_NBR_ID   1   /* Neighbors router ID, also can be 4 */
#define LIBNET_LINK_ID_IP_DES   2   /* IP address of designated router */
#define LIBNET_LINK_ID_SUB      3   /* IP subnet number */
    u_int rtr_link_data;    /* Depending on link_id, info is here */
    u_int8_t rtr_type;        /* Description of router link */
#define LIBNET_RTR_TYPE_PTP     1   /* Point-To-Point */
#define LIBNET_RTR_TYPE_TRANS   2   /* Connection to a "transit network" */
#define LIBNET_RTR_TYPE_STUB    3   /* Connectin to a "stub network" */
#define RTR_TYPE_VRTL   4   /* connects to a "virtual link" */
    u_int8_t rtr_tos_num;     /* number of different TOS metrics for this link */
    u_int16_t rtr_metric;     /* the "cost" of using this link */
};


/*
 *  Network LSA data format.
 */
struct libnet_net_lsa_hdr
{
    struct in_addr net_nmask;   /* Netmask for that network */
    u_int  net_rtr_id;          /* ID of router attached to that network */
};
 
 
/*
 *  Summary LSA data format.
 */
struct libnet_sum_lsa_hdr
{
    struct in_addr sum_nmask;   /* Netmask of destination IP address */
    u_int  sum_metric;          /* Same as in rtr_lsa (&0xfff to use last 24bit */
    u_int  sum_tos_metric;      /* first 8bits are TOS, 24bits are TOS Metric */
};
 
 
/*
 *  AS External LSA data format.
 *  & 0xfff logic operator for as_metric to get last 24bits.
 */
struct libnet_as_lsa_hdr
{
    struct in_addr as_nmask;    /* Netmask for advertised destination */
    u_int  as_metric;           /* May have to set E bit in first 8bits */
#define LIBNET_AS_E_BIT_ON 0x80000000  /* as_metric */
    struct in_addr as_fwd_addr; /* Forwarding address */
    u_int  as_rte_tag;          /* External route tag */
};


/*
 *  Base RIP header
 *  Routing Information Protocol
 *  Base header size: 24 bytes
 */
struct libnet_rip_hdr
{
    u_int8_t rip_cmd;         /* RIP command */
#define RIPCMD_REQUEST   1  /* want info */
#define RIPCMD_RESPONSE  2  /* responding to request */
#define RIPCMD_TRACEON   3  /* turn tracing on */
#define RIPCMD_TRACEOFF  4  /* turn it off */
#define RIPCMD_POLL      5  /* like request, but anyone answers */
#define RIPCMD_POLLENTRY 6  /* like poll, but for entire entry */
#define RIPCMD_MAX       7  /* ? command */
    u_int8_t rip_ver;         /* RIP version */
#define RIPVER_0         0
#define RIPVER_1         1
#define RIPVER_2         2
    u_int16_t rip_rd;         /* Zero (v1) or Routing Domain (v2) */
    u_int16_t rip_af;         /* Address family */
    u_int16_t rip_rt;         /* Zero (v1) or Route Tag (v2) */
    u_int32_t rip_addr;        /* IP address */
    u_int32_t rip_mask;        /* Zero (v1) or Subnet Mask (v2) */
    u_int32_t rip_next_hop;    /* Zero (v1) or Next hop IP address (v2) */
    u_int32_t rip_metric;      /* Metric */
};

/*
 *  RPC headers
 *  Remote Procedure Call
 */
#define LIBNET_RPC_CALL  0
#define LIBNET_RPC_REPLY 1
#define LIBNET_RPC_VERS  2
#define LIBNET_RPC_LAST_FRAG 0x80000000

/*
 *  Portmap defines
 */
#define LIBNET_PMAP_PROGRAM          100000
#define LIBNET_PMAP_PROC_NULL        0
#define LIBNET_PMAP_PROC_SET         1
#define LIBNET_PMAP_PROC_UNSET       2
#define LIBNET_PMAP_PROC_GETADDR     3
#define LIBNET_PMAP_PROC_DUMP        4
#define LIBNET_PMAP_PROC_CALLIT      5
#define LIBNET_PMAP_PROC_BCAST       5 /* Not a typo */
#define LIBNET_PMAP_PROC_GETTIME     6
#define LIBNET_PMAP_PROC_UADDR2TADDR 7
#define LIBNET_PMAP_PROC_TADDR2UADDR 8
#define LIBNET_PMAP_PROC_GETVERSADDR 9
#define LIBNET_PMAP_PROC_INDIRECT    10
#define LIBNET_PMAP_PROC_GETADDRLIST 11
#define LIBNET_PMAP_PROC_GETSTAT     12

/* There will be more to add... */

struct libnet_rpc_opaque_auth
{
    u_int32_t rpc_auth_flavor;
    u_int32_t rpc_auth_length;
//    u_int8_t *rpc_auth_data;
};

struct libnet_rpc_call
{
    u_int32_t rpc_rpcvers;   /* RPC version - must be 2 */
    u_int32_t rpc_prognum;   /* Program Number */
    u_int32_t rpc_vers;      /* Program Version */
    u_int32_t rpc_procedure; /* RPC procedure */
    struct libnet_rpc_opaque_auth rpc_credentials;
    struct libnet_rpc_opaque_auth rpc_verifier;
};

struct libnet_rpc_call_hdr
{
    u_int32_t rpc_xid;  /* xid (transaction identifier) */
    u_int32_t rpc_type;
    struct libnet_rpc_call  rpc_call;
};

struct libnet_rpc_call_tcp_hdr
{
    u_int32_t rpc_record_marking; /* used with byte stream protocols */
    struct libnet_rpc_call_hdr rpc_common;
};

/*
 *  STP configuration header
 *  Spanning Tree Protocol
 *  Static header size: 35 bytes
 */
struct libnet_stp_conf_hdr
{
    u_int16_t stp_id;         /* protocol id */
    u_int8_t stp_version;     /* protocol version */
    u_int8_t stp_bpdu_type;   /* bridge protocol data unit type */
    u_int8_t stp_flags;       /* control flags */
    u_int8_t stp_rootid[8];   /* root id */
    u_int32_t stp_rootpc;      /* root path cost */
    u_int8_t stp_bridgeid[8]; /* bridge id */
    u_int16_t stp_portid;     /* port id */
    u_int16_t stp_mage;       /* message age */
    u_int16_t stp_maxage;     /* max age */
    u_int16_t stp_hellot;     /* hello time */
    u_int16_t stp_fdelay;     /* forward delay */
};


/*
 *  STP topology change notification header
 *  Spanning Tree Protocol
 *  Static header size: 4 bytes
 */
struct libnet_stp_tcn_hdr
{
    u_int16_t stp_id;         /* protocol id */
    u_int8_t stp_version;     /* protocol version */
    u_int8_t stp_bpdu_type;   /* bridge protocol data unit type */
};


/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */




//#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
//#endif
//#if (LIBNET_BIG_ENDIAN)
//    u_int8_t th_off:4,        /* data offset */
//           th_x2:4;         /* (unused) */
//#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

/*
 *  Token Ring Header
 */
struct libnet_token_ring_addr
{
    u_int8_t  token_ring_addr_octet[6];        /* Token Ring address */
};

/*
 *  UDP header
 *  User Data Protocol
 *  Static header size: 8 bytes
 */
struct libnet_udp_hdr
{
    u_int16_t uh_sport;       /* soure port */
    u_int16_t uh_dport;       /* destination port */
    u_int16_t uh_ulen;        /* length */
    u_int16_t uh_sum;         /* checksum */
};

/*
 *  Sebek header
 *  Static header size: 48 bytes
 */
struct libnet_sebek_hdr
{
    u_int32_t magic;           /* identify packets that should be hidden */
    u_int16_t version;         /* protocol version, currently 1 */
#define SEBEK_PROTO_VERSION 1
    u_int16_t type;            /* type of record (read data is type 0, write data is type 1) */
#define SEBEK_TYPE_READ     0  /* Currently, only read is supported */
#define SEBEK_TYPE_WRITE    1
    u_int32_t counter;         /*  PDU counter used to identify when packet are lost */
    u_int32_t time_sec;        /* seconds since EPOCH according to the honeypot */
    u_int32_t time_usec;       /* residual microseconds */
    u_int32_t pid;             /* PID */
    u_int32_t uid;             /* UID */
    u_int32_t fd;              /* FD */
#define SEBEK_CMD_LENGTH   12
    u_int8_t cmd[SEBEK_CMD_LENGTH]; /* 12 first characters of the command */
    u_int32_t length;          /* length in bytes of the PDU's body */
};


/*
 *  VRRP header
 *  Virtual Router Redundancy Protocol
 *  Static header size: 8 bytes
 */
#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP 112    /* not everyone's got this */
#endif
struct libnet_vrrp_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t vrrp_v:4,        /* protocol version */
           vrrp_t:4;        /* packet type */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t vrrp_t:4,        /* packet type */
           vrrp_v:4;        /* protocol version */
#endif
#define LIBNET_VRRP_VERSION_01  0x1
#define LIBNET_VRRP_VERSION_02  0x2
#define LIBNET_VRRP_TYPE_ADVERT 0x1
    u_int8_t vrrp_vrouter_id; /* virtual router id */
    u_int8_t vrrp_priority;   /* priority */
    u_int8_t vrrp_ip_count;   /* number of IP addresses */
    u_int8_t vrrp_auth_type;  /* authorization type */
#define LIBNET_VRRP_AUTH_NONE   0x1
#define LIBNET_VRRP_AUTH_PASSWD 0x2
#define LIBNET_VRRP_AUTH_IPAH   0x3
    u_int8_t vrrp_advert_int; /* advertisement interval */
    u_int16_t vrrp_sum;       /* checksum */
    /* additional addresses */
    /* authentication info */
};



/* EOF */
