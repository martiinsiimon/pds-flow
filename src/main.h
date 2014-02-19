/*
 * File:   main.h
 * Author: Martin Simon <martiinsiimon@gmail.com>
 */

#ifndef MAIN_H
#define	MAIN_H

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
        uint16_t port;
        struct in6_addr addr;
    };
    uint64_t packets;
    uint64_t bytes;
    char used;
};

struct t_hashTable
{
    int size;
    int count;
    struct t_dataStruct * data;
};

/* Sort key values */
#define EN_SORT_SRCPORT 1
#define EN_SORT_DSTPORT 2
#define EN_SORT_PACKETS 3
#define EN_SORT_BYTES 4

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
#define EN_HASH_INIT_IP 131072
#define EN_HASH_INIT_PORT 16384
#define EN_HASH_STEP 13

#define SA_FAMILY_IPV6 167772160
#define SA_FAMILY_IPV4 33554432
#define IPV4_FULL_MASK 4294967295 //address 255.255.255.255

/* IPv4 masks */
#define IPV4_MASK_32 4294967295 //address 255.255.255.255
#define IPV4_MASK_31 4278190079 //address 255.255.255.254
#define IPV4_MASK_30 4244635647 //address 255.255.255.252
#define IPV4_MASK_29 4177526783 //address 255.255.255.248
#define IPV4_MASK_28 4043309055 //address 255.255.255.240
#define IPV4_MASK_27 3774873599 //address 255.255.255.224
#define IPV4_MASK_26 3238002687 //address 255.255.255.192
#define IPV4_MASK_25 2164260863 //address 255.255.255.128
#define IPV4_MASK_24 16777215   //address 255.255.255.0
#define IPV4_MASK_23 16711679   //address 255.255.254.0
#define IPV4_MASK_22 16580607   //address 255.255.252.0
#define IPV4_MASK_21 16318463   //address 255.255.248.0
#define IPV4_MASK_20 15794175   //address 255.255.240.0
#define IPV4_MASK_19 14745599   //address 255.255.224.0
#define IPV4_MASK_18 12648447   //address 255.255.192.0
#define IPV4_MASK_17 8454143    //address 255.255.128.0
#define IPV4_MASK_16 65535      //address 255.255.0.0
#define IPV4_MASK_15 65279      //address 255.254.0.0
#define IPV4_MASK_14 64767      //address 255.252.0.0
#define IPV4_MASK_13 63743      //address 255.248.0.0
#define IPV4_MASK_12 61695      //address 255.240.0.0
#define IPV4_MASK_11 57599      //address 255.224.0.0
#define IPV4_MASK_10 49407      //address 255.192.0.0
#define IPV4_MASK_9  33023      //address 255.128.0.0
#define IPV4_MASK_8  255        //address 255.0.0.0
#define IPV4_MASK_7  254        //address 254.0.0.0
#define IPV4_MASK_6  252        //address 252.0.0.0
#define IPV4_MASK_5  248        //address 248.0.0.0
#define IPV4_MASK_4  240        //address 240.0.0.0
#define IPV4_MASK_3  224        //address 224.0.0.0
#define IPV4_MASK_2  192        //address 192.0.0.0
#define IPV4_MASK_1  128        //address 128.0.0.0


static unsigned int masks[] = {
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

int parseSortKey(char *key);
int parseAggKey(char *key, int * mask);
void addRecordIP(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable);
void addRecordPort(struct flow *fl, int aggkey, struct t_hashTable *hashTable);

inline unsigned int hashFunction(const unsigned int input, unsigned tableSize);
void initHashTable(struct t_hashTable *hashTable, unsigned int tableSize);
void finishHashTable(struct t_hashTable *hashTable);
#endif /* MAIN_H */