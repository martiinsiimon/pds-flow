/*
 * File:    main.h
 * Author:  Martin Simon <martiinsiimon@gmail.com>
 * License: See the LICENSE file
 */

#ifndef MAIN_H
#define	MAIN_H


#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>


struct flow
{
    uint32_t sa_family;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t packets;
    uint64_t bytes;
};

struct t_dataStruct
{
    union
    {
        uint16_t port; //in order
        uint32_t addr4; //in order
        struct in6_addr addr6; //uint32_t[4]
    } _union_dataStruct;
#define port _union_dataStruct.port
#define addr4 _union_dataStruct.addr4
#define addr6 _union_dataStruct.addr6

    uint64_t packets;
    uint64_t bytes;
    char used;
};

struct t_sortStruct
{
    uint32_t key;
    uint64_t value;
};


struct t_hashTable
{
    uint32_t size;
    uint32_t count;
    uint32_t limit; //limit is precomputed by 0.8*size;
    struct t_dataStruct * data;
};

/* Sort key values */
#define EN_SORT_PACKETS 1
#define EN_SORT_BYTES 2

/* Aggregation key values */
#define EN_AGG_SRCIP 1
#define EN_AGG_DSTIP 2
#define EN_AGG_SRCIP4 3
#define EN_AGG_DSTIP4 4
#define EN_AGG_SRCIP6 5
#define EN_AGG_DSTIP6 6
#define EN_AGG_SRCPORT 7
#define EN_AGG_DSTPORT 8

/* Other values */
#define EN_ERROR -1
#define EN_HASH_INIT_IP 16384
#define EN_HASH_INIT_PORT 16384
#define EN_HASH_STEP 13

#define SA_FAMILY_IPV6 167772160
#define SA_FAMILY_IPV4 33554432
#define IPV4_FULL_MASK 4294967295 //address 255.255.255.255

/* IPv4 masks */
static uint32_t masks[] = {
    0,
    128, //address 128.0.0.0
    192, //address 192.0.0.0
    224, //address 224.0.0.0
    240, //address 240.0.0.0
    248, //address 248.0.0.0
    252, //address 252.0.0.0
    254, //address 254.0.0.0
    255, //address 255.0.0.0
    33023, //address 255.128.0.0
    49407, //address 255.192.0.0
    57599, //address 255.224.0.0
    61695, //address 255.240.0.0
    63743, //address 255.248.0.0
    64767, //address 255.252.0.0
    65279, //address 255.254.0.0
    65535, //address 255.255.0.0
    8454143, //address 255.255.128.0
    12648447, //address 255.255.192.0
    14745599, //address 255.255.224.0
    15794175, //address 255.255.240.0
    16318463, //address 255.255.248.0
    16580607, //address 255.255.252.0
    16711679, //address 255.255.254.0
    16777215, //address 255.255.255.0
    2164260863, //address 255.255.255.128
    3238002687, //address 255.255.255.196
    3774873599, //address 255.255.255.224
    4043309055, //address 255.255.255.240
    4177526783, //address 255.255.255.248
    4244635647, //address 255.255.255.252
    4278190079, //address 255.255.255.254
    4294967295, //address 255.255.255.255
};


/* Prototypes */
void print_flow(struct flow *fl);
void printHelp(char *name);
void printError(char *msg);
void printIpv6(struct t_dataStruct *d);
void printIpv4(struct t_dataStruct *d);
void printPort(struct t_dataStruct *d);

char equals_in6_addr(struct in6_addr *i1, struct in6_addr *i2);
struct in6_addr ntoh128(struct in6_addr n);
struct in6_addr maskIPv6(struct in6_addr* addr, int mask);
int compareSortStruct(const void * a, const void * b);
int sortHashArray(struct t_sortStruct *hashArray, struct t_hashTable *hashTable, int sortkey);

int parseSortKey(char *key);
int parseAggKey(char *key, int * mask);
void addRecordIP(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable4, struct t_hashTable *hashTable6);
void addRecordIP4(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable);
void addRecordIP6(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable);
void addRecordPort(struct flow *fl, int aggkey, struct t_hashTable *hashTable);

uint32_t hashFunction(const uint32_t input, uint32_t tableSize);
uint32_t hashFunction6(const struct in6_addr input, uint32_t tableSize);
void initHashTable(struct t_hashTable *hashTable, uint32_t tableSize);
void doubleHashTable(struct t_hashTable *hashTable, int aggkey, int mask);
void finishHashTable(struct t_hashTable *hashTable);
#endif /* MAIN_H */