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
    //int half;
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
#define EN_AGG_SRCPORT 3
#define EN_AGG_DSTPORT 4

/* Other values */
#define EN_ERROR -1
#define EN_HASH_INIT_IP 2048
#define EN_HASH_INIT_PORT 2048
#define EN_HASH_STEP 13

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