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

struct data_struct
{
    union
    {
        uint16_t port;
        struct in6_addr addr;
    };
    uint64_t packets;
    uint64_t bytes;
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

/* Prototypes */
void print_flow(struct flow *fl);
void printHelp(char *name);
void printError(char *msg);

int parseSortKey(char *key);
int parseAggKey(char *key, int * mask);
void addRecord(struct flow *fl, int agsign, int mask);

#endif /* MAIN_H */