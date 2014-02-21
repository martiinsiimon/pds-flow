/*
 * File:    main.c
 * Author:  Martin Simon <martiinsiimon@gmail.com>
 * License: See the LICENSE file
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
//#include <sys/types.h>

#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>
#include "main.h"

void print_flow(struct flow *fl)
{
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];
    if (fl->sa_family == SA_FAMILY_IPV4)
    {
        printf("family: ipv4\n");
        inet_ntop(AF_INET, &(fl->src_addr.__in6_u.__u6_addr32[3]), srcip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(fl->dst_addr.__in6_u.__u6_addr32[3]), dstip, INET_ADDRSTRLEN);
    }
    else
    {
        printf("family: ipv6\n");
        inet_ntop(AF_INET6, &(fl->src_addr), srcip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(fl->dst_addr), dstip, INET6_ADDRSTRLEN);
    }

    fprintf(stdout, "%s:%d -> %s:%d, pkts: %"PRIi64" , bytes: %"PRIi64" \n", srcip, ntohs(fl->src_port), dstip, ntohs(fl->dst_port), __builtin_bswap64(fl->packets), __builtin_bswap64(fl->bytes));
}

void printHelp(char *name)
{
    fprintf(stdout, "Usage: %s -f directory -a aggregation -s sort\n", name);
    fprintf(stdout, "       %s -h\n", name);
    fprintf(stdout, "       %s --help\n", name);
    fprintf(stdout, "    directory    directory with flow data files\n");
    fprintf(stdout, "    aggregation  aggregation key [srcip, dstip, srcip4/mask, dstip4/mask,\n"
            "                 srcip6/mask, dstip6/mask, srcport, dstport]\n");
    fprintf(stdout, "    sort         sort key [packets, bytes]\n\n");
}

inline void printError(char *msg)
{
    fprintf(stderr, "ERR: %s\n", msg);
}

int parseSortKey(char *key)
{
    if (strcmp(key, "packets") == 0)
        return EN_SORT_PACKETS;
    else if (strcmp(key, "bytes") == 0)
        return EN_SORT_BYTES;
    else
        return EN_ERROR;
}

int parseAggKey(char *key, int * mask)
{
    char * p = strchr(key, '/');
    if (p != NULL)
    {
        if (p - key == strlen(key) - 1)
            return EN_ERROR;

        char * tmpKey = malloc((p - key + 1) * sizeof (char));
        strncpy(tmpKey, key, p - key);
        tmpKey[p - key] = '\0';

        char *tmpMask = malloc((strlen(key) - (p - key)) * sizeof (char));
        strncpy(tmpMask, key + (p - key) + 1, (strlen(key) - (p - key) - 1));
        tmpMask[strlen(key) - (p - key) - 1] = '\0';
        *mask = atoi(tmpMask);
        free(tmpMask);

        int result;

        if (strcmp(tmpKey, "srcip4") == 0 && *mask <= 32 && *mask > 0)
            result = EN_AGG_SRCIP4;
        else if (strcmp(tmpKey, "dstip4") == 0 && *mask <= 32 && *mask > 0)
            result = EN_AGG_DSTIP4;
        else if (strcmp(tmpKey, "srcip6") == 0 && *mask <= 128 && *mask > 0)
            result = EN_AGG_SRCIP6;
        else if (strcmp(tmpKey, "dstip6") == 0 && *mask <= 128 && *mask > 0)
            result = EN_AGG_DSTIP6;
        else
            result = EN_ERROR;

        free(tmpKey);
        return result;
    }
    else if (strcmp(key, "srcip") == 0)
        return EN_AGG_SRCIP;
    else if (strcmp(key, "dstip") == 0)
        return EN_AGG_DSTIP;
    else if (strcmp(key, "srcport") == 0)
        return EN_AGG_SRCPORT;
    else if (strcmp(key, "dstport") == 0)
        return EN_AGG_DSTPORT;
    else
        return EN_ERROR;
}

void addRecordIP(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable4, struct t_hashTable *hashTable6)
{
    if (aggkey == EN_AGG_SRCIP4 || aggkey == EN_AGG_DSTIP4)
    {
        /* Skip unwanted IP flows (by protocol version) */
        if (fl->sa_family == SA_FAMILY_IPV6)
        {
            return;
        }

        /* Add IPv4 record to the hash table */
        addRecordIP4(fl, aggkey, mask, hashTable4);

        /* Check the size of hash table and double it if necessary */
        if (hashTable4->count > hashTable4->limit)
        {
            doubleHashTable(hashTable4, aggkey, mask);
        }
    }
    else if (aggkey == EN_AGG_SRCIP6 || aggkey == EN_AGG_DSTIP6)
    {
        /* Skip unwanted IP flows (by protocol version) */
        if (fl->sa_family == SA_FAMILY_IPV4)
        {
            return;
        }

        /* Add IPv6 record to the hash table */
        addRecordIP6(fl, aggkey, mask, hashTable6);

        /* Check the size of hash table and double it if necessary */
        if (hashTable6->count > hashTable6->limit)
        {
            doubleHashTable(hashTable6, aggkey, mask);
        }
    }
    else /* aggkey == EN_AGG_SRCIP || aggkey == EN_AGG_DSTIP */
    {
        /* Process IPv6 addresses */
        if (fl->sa_family == SA_FAMILY_IPV6)
        {
            mask = 128;
            if (aggkey == EN_AGG_SRCIP)
                aggkey = EN_AGG_SRCIP6;
            else
                aggkey = EN_AGG_DSTIP6;

            /* Add IPv6 record to the hash table */
            addRecordIP6(fl, aggkey, mask, hashTable6);

            /* Check the size of hash table and double it if necessary */
            if (hashTable6->count > hashTable6->limit)
            {
                doubleHashTable(hashTable6, aggkey, mask);
            }
        }
        else /* fl->sa_family == SA_FAMILY_IPV4 */
        {
            mask = 32;
            if (aggkey == EN_AGG_SRCIP)
                aggkey = EN_AGG_SRCIP4;
            else
                aggkey = EN_AGG_DSTIP4;

            /* Add IPv4 record to the hash table */
            addRecordIP4(fl, aggkey, mask, hashTable4);

            /* Check the size of hash table and double it if necessary */
            if (hashTable4->count > hashTable4->limit)
            {
                doubleHashTable(hashTable4, aggkey, mask);
            }
        }
    }
}

void addRecordIP6(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable)
{
    return; //DBG//////////////////////////////////////////////////////
    /* Get correct address */
    struct in6_addr ipaddr;
    if (aggkey == EN_AGG_SRCIP6)
        ipaddr = fl->src_addr;
    else
        ipaddr = fl->dst_addr;

    /* Get masked address */
    struct in6_addr maskedAddr; // = masks6[mask] & ntoh128(ipaddr);

    /* Get the hash */
    uint32_t hash = hashFunction6(maskedAddr, hashTable->size);

    /* Add the record */
    if (hashTable->data[hash].used)
    {
        if (equals_in6_addr(&(hashTable->data[hash].addr6), &maskedAddr))
        {
            hashTable->data[hash].bytes += ntohl(fl->bytes);
            hashTable->data[hash].packets += ntohl(fl->packets);
        }
        else
        {
            uint32_t newHash = (hash + EN_HASH_STEP) % hashTable->size;

            while (hashTable->data[newHash].used && !equals_in6_addr(&(hashTable->data[newHash].addr6), &maskedAddr))
            {
                newHash = (newHash + EN_HASH_STEP) % hashTable->size;
            }

            if (!hashTable->data[newHash].used)
            {
                hashTable->data[newHash].addr6 = maskedAddr;
                hashTable->data[newHash].bytes = ntohl(fl->bytes);
                hashTable->data[newHash].packets = ntohl(fl->packets);
                hashTable->data[newHash].used = 1;
                hashTable->count++;
            }
            else
            {
                hashTable->data[newHash].bytes += ntohl(fl->bytes);
                hashTable->data[newHash].packets += ntohl(fl->packets);
            }
        }
    }
        /* Initialize if there is not a record yet */
    else
    {
        hashTable->data[hash].addr6 = maskedAddr;
        hashTable->data[hash].bytes = fl->bytes;
        hashTable->data[hash].packets = fl->packets;
        hashTable->data[hash].used = 1;
        hashTable->count++;
    }
}

void addRecordIP4(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable)
{
    /* Get correct address */
    uint32_t ipaddr;
    if (aggkey == EN_AGG_SRCIP4)
        ipaddr = fl->src_addr.__in6_u.__u6_addr32[3];
    else
        ipaddr = fl->dst_addr.__in6_u.__u6_addr32[3];

    /* Get masked address */
    uint32_t maskedAddr = ntohl(masks[mask] & ipaddr);

    /* Get the hash */
    uint32_t hash = hashFunction(maskedAddr, hashTable->size);

    /* Add the record */
    if (hashTable->data[hash].used)
    {
        if (hashTable->data[hash].addr4 == maskedAddr)
        {
            hashTable->data[hash].bytes += __builtin_bswap64(fl->bytes);
            hashTable->data[hash].packets += __builtin_bswap64(fl->packets);
        }
        else
        {
            uint32_t newHash = (uint32_t) (hash + EN_HASH_STEP) % hashTable->size;

            while (hashTable->data[newHash].used && hashTable->data[newHash].addr4 != maskedAddr)
            {
                newHash = (newHash + EN_HASH_STEP) % hashTable->size;
            }

            if (!hashTable->data[newHash].used)
            {
                hashTable->data[newHash].addr4 = maskedAddr;
                hashTable->data[newHash].bytes = __builtin_bswap64(fl->bytes);
                hashTable->data[newHash].packets = __builtin_bswap64(fl->packets);
                hashTable->data[newHash].used = 1;
                hashTable->count++;
            }
            else
            {
                hashTable->data[newHash].bytes += __builtin_bswap64(fl->bytes);
                hashTable->data[newHash].packets += __builtin_bswap64(fl->packets);
            }
        }
    }
        /* Initialize if there is not a record yet */
    else
    {
        hashTable->data[hash].addr4 = maskedAddr;
        hashTable->data[hash].bytes = __builtin_bswap64(fl->bytes);
        hashTable->data[hash].packets = __builtin_bswap64(fl->packets);
        hashTable->data[hash].used = 1;
        hashTable->count++;
    }
}

void addRecordPort(struct flow *fl, int aggkey, struct t_hashTable *hashTable)
{
    /* Try to add a record to data structure */
    uint32_t value;
    if (aggkey == EN_AGG_SRCPORT)
        value = ntohs(fl->src_port);
    else if (aggkey == EN_AGG_DSTPORT)
        value = ntohs(fl->dst_port);
    else
        return;

    /* Get the hash */
    uint32_t hash = hashFunction(value, hashTable->size);

    /* Add if there is a record */
    if (hashTable->data[hash].used)
    {
        if (hashTable->data[hash].port == value)
        {
            hashTable->data[hash].bytes += __builtin_bswap64(fl->bytes);
            hashTable->data[hash].packets += __builtin_bswap64(fl->packets);
        }
        else
        {
            uint32_t newHash = (hash + EN_HASH_STEP) % hashTable->size;

            while (hashTable->data[newHash].used && hashTable->data[newHash].port != value)
            {
                newHash = (newHash + EN_HASH_STEP) % hashTable->size;
            }

            if (!hashTable->data[newHash].used)
            {
                hashTable->data[newHash].port = value;
                hashTable->data[newHash].bytes = __builtin_bswap64(fl->bytes);
                hashTable->data[newHash].packets = __builtin_bswap64(fl->packets);
                hashTable->data[newHash].used = 1;
                hashTable->count++;
            }
            else
            {
                hashTable->data[newHash].bytes += __builtin_bswap64(fl->bytes);
                hashTable->data[newHash].packets += __builtin_bswap64(fl->packets);
            }
        }
    }
    /* Initialize if there is not a record yet */
    else
    {
        hashTable->data[hash].port = value;
        hashTable->data[hash].bytes = __builtin_bswap64(fl->bytes);
        hashTable->data[hash].packets = __builtin_bswap64(fl->packets);
        hashTable->data[hash].used = 1;
        hashTable->count++;
    }

    if (hashTable->count > hashTable->limit)
    {
        doubleHashTable(hashTable, aggkey, 0);
    }
}

char equals_in6_addr(struct in6_addr *i1, struct in6_addr *i2)
{
    if (i1->__in6_u.__u6_addr32[0] == i2->__in6_u.__u6_addr32[0] &&
        i1->__in6_u.__u6_addr32[1] == i2->__in6_u.__u6_addr32[1] &&
        i1->__in6_u.__u6_addr32[2] == i2->__in6_u.__u6_addr32[2] &&
        i1->__in6_u.__u6_addr32[3] == i2->__in6_u.__u6_addr32[3])
        return 1;
    return 0;
}

void doubleHashTable(struct t_hashTable *hashTable, int aggkey, int mask)
{
    printf("Hash table out of resources! size: %d/%d\n", hashTable->count, hashTable->size);
    struct t_dataStruct *oldDataStruct = hashTable->data;
    uint32_t oldSize = hashTable->size;
    initHashTable(hashTable, oldSize * 2);

    struct flow tmpFl;

    uint32_t i;
    for (i = 0; i < oldSize; i++)
    {
        if (oldDataStruct[i].used)
        {
            tmpFl.bytes = oldDataStruct[i].bytes;
            tmpFl.packets = oldDataStruct[i].packets;
            if (aggkey == EN_AGG_SRCIP4)
            {
                tmpFl.src_addr.__in6_u.__u6_addr32[3] = htonl(oldDataStruct[i].addr4);
                addRecordIP4(&tmpFl, aggkey, mask, hashTable);
            }
            else if (aggkey == EN_AGG_DSTIP4)
            {
                tmpFl.dst_addr.__in6_u.__u6_addr32[3] = htonl(oldDataStruct[i].addr4);
                addRecordIP4(&tmpFl, aggkey, mask, hashTable);
            }
            else if (aggkey == EN_AGG_SRCIP6)
            {
                tmpFl.src_addr = oldDataStruct[i].addr6;
                addRecordIP6(&tmpFl, aggkey, mask, hashTable);
            }
            else if (aggkey == EN_AGG_DSTIP6)
            {
                tmpFl.dst_addr = oldDataStruct[i].addr6;
                addRecordIP6(&tmpFl, aggkey, mask, hashTable);
            }
            else if (aggkey == EN_AGG_SRCPORT)
            {
                tmpFl.src_port = oldDataStruct[i].port;
                addRecordPort(&tmpFl, aggkey, hashTable);
            }
            else if (aggkey == EN_AGG_DSTPORT)
            {
                tmpFl.dst_port = oldDataStruct[i].port;
                addRecordPort(&tmpFl, aggkey, hashTable);
            }
            else
                break;
        }
    }
    free(oldDataStruct);
}

inline uint32_t hashFunction(const uint32_t input, uint32_t tableSize)
{
    return ((uint32_t) (input * 2654435761) % tableSize);
}


inline uint32_t hashFunction6(const struct in6_addr input, uint32_t tableSize)
{
    return ((input.__in6_u.__u6_addr32[0] *
             input.__in6_u.__u6_addr32[1] *
             input.__in6_u.__u6_addr32[2] *
             input.__in6_u.__u6_addr32[3] *
             2654435761) % tableSize);
}

void initHashTable(struct t_hashTable *hashTable, uint32_t tableSize)
{
    hashTable->data = malloc(sizeof (struct t_dataStruct) * tableSize);
    hashTable->size = tableSize;
    hashTable->count = 0;
    hashTable->limit = 0.8 * tableSize;

    uint32_t i;
    for (i = 0; i < tableSize; i++)
    {
        hashTable->data[i].used = 0;
    }
}

void finishHashTable(struct t_hashTable *hashTable)
{
    if (hashTable != NULL)
    {
        free(hashTable->data);
        free(hashTable);
    }
}

struct in6_addr ntoh128(struct in6_addr n)
{
    struct in6_addr h;
    h.__in6_u.__u6_addr32[0] = ntohl(n.__in6_u.__u6_addr32[0]);
    h.__in6_u.__u6_addr32[1] = ntohl(n.__in6_u.__u6_addr32[1]);
    h.__in6_u.__u6_addr32[2] = ntohl(n.__in6_u.__u6_addr32[2]);
    h.__in6_u.__u6_addr32[3] = ntohl(n.__in6_u.__u6_addr32[3]);
    return h;
}


int main(int argc, char *argv[])
{
    char *directory;
    int sortkey;
    int aggkey;
    int mask = 0;
    struct t_hashTable *hashTable = malloc(sizeof (struct t_hashTable));
    struct t_hashTable *hashTable6 = NULL;

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        /* Help requested */
        printHelp(argv[0]);
        return (EXIT_SUCCESS);
    }
    else if (argc == 7 && strcmp(argv[1], "-f") == 0 && strcmp(argv[3], "-a") == 0 && strcmp(argv[5], "-s") == 0)
    {
        /* Correct parameters */
        directory = argv[2]; /* Will be checked by openning */

        /* Check aggkey */
        if ((aggkey = parseAggKey(argv[4], &mask)) == EN_ERROR)
        {
            printError("Invalid aggregation key!");
            printHelp(argv[0]);
            return (EXIT_FAILURE);
        }

        /* Check sortkey */
        if ((sortkey = parseSortKey(argv[6])) == EN_ERROR)
        {
            printError("Invalid sort key!");
            printHelp(argv[0]);
            return (EXIT_FAILURE);
        }
    }
    else
    {
        /* Invalid parameters! */
        printError("Invalid parameters!");
        printHelp(argv[0]);
        return (EXIT_FAILURE);
    }

    // DBG ////////////////////////////////////////////////
    //unsigned int a = 0;
    // ENDDBG /////////////////////////////////////////////

    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(directory)) != NULL)
    {
        //FIXME: every file should be in separated thread with separated data structure
        //FIXME2: should get list of files recursively

        if (aggkey == EN_AGG_SRCIP ||
            aggkey == EN_AGG_DSTIP ||
            aggkey == EN_AGG_SRCIP4 ||
            aggkey == EN_AGG_DSTIP4 ||
            aggkey == EN_AGG_SRCIP6 ||
            aggkey == EN_AGG_DSTIP6)
        {
            /* Initialize hash function for IP based data structure */
            initHashTable(hashTable, EN_HASH_INIT_IP);
            hashTable6 = malloc(sizeof (struct t_hashTable));
            initHashTable(hashTable6, EN_HASH_INIT_IP);
        }
        else
        {
            /* Initialize hash function for port based data structure */
            initHashTable(hashTable, EN_HASH_INIT_PORT);
        }

        while ((ent = readdir(dir)) != NULL)
        {
            /* Skip special unix files . and .. */
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;

            /* Get file name */
            char * file = malloc(strlen(ent->d_name) + strlen(directory) + 1 + 1);
            strcpy(file, directory);
            strcat(file, "/");
            strcat(file, ent->d_name);

            // DBG //////////////////////////////////////////////
            fprintf(stdout, "%s\n", file);
            // ENDDBG ///////////////////////////////////////////

            /* Start to parse file by chosen aggregation */
            FILE *fp = fopen(file, "rb");
            struct flow fl;
            size_t n = 0;

            if (aggkey == EN_AGG_SRCIP ||
                aggkey == EN_AGG_DSTIP ||
                aggkey == EN_AGG_SRCIP4 ||
                aggkey == EN_AGG_DSTIP4 ||
                aggkey == EN_AGG_SRCIP6 ||
                aggkey == EN_AGG_DSTIP6)
            {
                while ((n = fread(&fl, sizeof (struct flow), 1, fp)) != 0)
                {
                    addRecordIP(&fl, aggkey, mask, hashTable, hashTable6);
                }
            }
            else
            {
                while ((n = fread(&fl, sizeof (struct flow), 1, fp)) != 0)
                {
                    addRecordPort(&fl, aggkey, hashTable);
                }
            }

            // DBG ////////////////////////////////
            //fprintf(stdout, "%d\n", a);
            printf("count/size: %u/%u\n", hashTable->count, hashTable->size);
            // ENDDBG /////////////////////////////

            /* Close the file */
            fclose(fp);

            /* Free the file name */
            free(file);
        }
        closedir(dir);
    }
    else
    {
        /* Unable to open directory */
        printError("Unable to open given directory!");
        return (EXIT_FAILURE);
    }

    /* Sort the internal structure */
    /* TODO */

    /* Print the sorted internal structure */
    /* TODO */

    finishHashTable(hashTable);
    finishHashTable(hashTable6);
    return (EXIT_SUCCESS);
}
