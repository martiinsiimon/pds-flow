/*
 * File:    main.c
 * Author:  Martin Simon <martiinsiimon@gmail.com>
 * License: See the LICENSE file
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>
#include "main.h"

void printData(struct t_dataStruct *d)
{
    if (d->used == EN_DATA_PORT)
    {
        printf("%d,%lu,%lu\n", d->port, d->packets, d->bytes);

    }
    else if (d->used == EN_DATA_IP4)
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(d->addr4), ip, INET_ADDRSTRLEN);
        printf("%s,%lu,%lu\n", ip, d->packets, d->bytes);
    }
    else if (d->used == EN_DATA_IP6)
    {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(d->addr6), ip, INET6_ADDRSTRLEN);
        printf("%s,%lu,%lu\n", ip, d->packets, d->bytes);
    }
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
        if ((size_t) (p - key + 1) == strlen(key))
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

void addRecordIP(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable)
{
    if (aggkey == EN_AGG_SRCIP4 || aggkey == EN_AGG_DSTIP4)
    {
        /* Skip unwanted IP flows (by protocol version) */
        if (fl->sa_family == SA_FAMILY_IPV6)
        {
            return;
        }

        /* Add IPv4 record to the hash table */
        addRecordIP4(fl, aggkey, mask, hashTable);

        /* Check the size of hash table and double it if necessary */
        if (hashTable->count > hashTable->limit)
        {
            doubleHashTable(hashTable, aggkey);
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
        addRecordIP6(fl, aggkey, mask, hashTable);

        /* Check the size of hash table and double it if necessary */
        if (hashTable->count > hashTable->limit)
        {
            doubleHashTable(hashTable, aggkey);
        }
    }
    else /* aggkey == EN_AGG_SRCIP || aggkey == EN_AGG_DSTIP */
    {
        /* Process IPv6 addresses */
        if (fl->sa_family == SA_FAMILY_IPV6)
        {
            mask = 128;

            /* Add IPv6 record to the hash table */
            addRecordIP6(fl, aggkey, mask, hashTable);

            /* Check the size of hash table and double it if necessary */
            if (hashTable->count > hashTable->limit)
            {
                doubleHashTable(hashTable, aggkey);
            }
        }
        else /* fl->sa_family == SA_FAMILY_IPV4 */
        {
            mask = 32;

            /* Add IPv4 record to the hash table */
            addRecordIP4(fl, aggkey, mask, hashTable);

            /* Check the size of hash table and double it if necessary */
            if (hashTable->count > hashTable->limit)
            {
                doubleHashTable(hashTable, aggkey);
            }
        }
    }
}

void addRecordIP6(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable)
{
    /* Get correct address */
    struct in6_addr ipaddr;
    if (aggkey == EN_AGG_SRCIP6 || aggkey == EN_AGG_SRCIP)
        ipaddr = fl->src_addr;
    else
        ipaddr = fl->dst_addr;

    /* Get masked address */
    struct in6_addr maskedAddr = maskIPv6(&ipaddr, mask);

    /* Get the hash */
    uint32_t hash = hashFunction6(maskedAddr, hashTable->size);

    /* Add the record */
    if (hashTable->data[hash].used != EN_DATA_UNUSED)
    {
        if (hashTable->data[hash].used == EN_DATA_IP6 && equals_in6_addr(&(hashTable->data[hash].addr6), &maskedAddr))
        {
            hashTable->data[hash].bytes += __builtin_bswap64(fl->bytes);
            hashTable->data[hash].packets += __builtin_bswap64(fl->packets);
        }
        else
        {
            uint32_t newHash = (hash + EN_HASH_STEP) % hashTable->size;

            while ((hashTable->data[newHash].used == EN_DATA_IP6 && !equals_in6_addr(&(hashTable->data[newHash].addr6), &maskedAddr)) || hashTable->data[newHash].used == EN_DATA_IP4 || hashTable->data[hash].used == EN_DATA_PORT)
            {
                newHash = (uint32_t) (newHash + EN_HASH_STEP) % hashTable->size;
            }

            if (hashTable->data[newHash].used == EN_DATA_UNUSED)
            {
                hashTable->data[newHash].addr6 = maskedAddr;
                hashTable->data[newHash].bytes = __builtin_bswap64(fl->bytes);
                hashTable->data[newHash].packets = __builtin_bswap64(fl->packets);
                hashTable->data[newHash].used = EN_DATA_IP6;
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
        hashTable->data[hash].addr6 = maskedAddr;
        hashTable->data[hash].bytes = __builtin_bswap64(fl->bytes);
        hashTable->data[hash].packets = __builtin_bswap64(fl->packets);
        hashTable->data[hash].used = EN_DATA_IP6;
        hashTable->count++;
    }
}

void addRecordIP4(struct flow *fl, int aggkey, int mask, struct t_hashTable *hashTable)
{
    /* Get correct address */
    uint32_t ipaddr;
    if (aggkey == EN_AGG_SRCIP4 || aggkey == EN_AGG_SRCIP)
        ipaddr = fl->src_addr.s6_addr32[3];
    else
        ipaddr = fl->dst_addr.s6_addr32[3];

    /* Get masked address */
    uint32_t maskedAddr;
    if (mask == 32)
        maskedAddr = ipaddr;
    else
        maskedAddr = ipaddr & masks[mask];

    /* Get the hash */
    uint32_t hash = hashFunction(maskedAddr, hashTable->size);

    /* Add the record */
    if (hashTable->data[hash].used != EN_DATA_UNUSED)
    {
        if (hashTable->data[hash].used == EN_DATA_IP4 && hashTable->data[hash].addr4 == maskedAddr)
        {
            hashTable->data[hash].bytes += __builtin_bswap64(fl->bytes);
            hashTable->data[hash].packets += __builtin_bswap64(fl->packets);
        }
        else
        {
            uint32_t newHash = (uint32_t) (hash + EN_HASH_STEP) % hashTable->size;

            while ((hashTable->data[newHash].used == EN_DATA_IP4 && hashTable->data[newHash].addr4 != maskedAddr) || hashTable->data[newHash].used == EN_DATA_IP6 || hashTable->data[hash].used == EN_DATA_PORT)
            {
                newHash = (newHash + EN_HASH_STEP) % hashTable->size;
            }

            if (hashTable->data[newHash].used == EN_DATA_UNUSED)
            {
                hashTable->data[newHash].addr4 = maskedAddr;
                hashTable->data[newHash].bytes = __builtin_bswap64(fl->bytes);
                hashTable->data[newHash].packets = __builtin_bswap64(fl->packets);
                hashTable->data[newHash].used = EN_DATA_IP4;
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
        hashTable->data[hash].used = EN_DATA_IP4;
        hashTable->count++;
    }
}

void addRecordPort(struct flow *fl, int aggkey, struct t_hashTable *hashTable)
{
    /* Try to add a record to data structure */
    uint32_t value;
    if (aggkey == EN_AGG_SRCPORT)
        value = __builtin_bswap16(fl->src_port);
    else if (aggkey == EN_AGG_DSTPORT)
        value = __builtin_bswap16(fl->dst_port);
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
                hashTable->data[newHash].used = EN_DATA_PORT;
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
        hashTable->data[hash].used = EN_DATA_PORT;
        hashTable->count++;
    }

    if (hashTable->count > hashTable->limit)
    {
        doubleHashTable(hashTable, aggkey);
    }
}

char equals_in6_addr(struct in6_addr *i1, struct in6_addr *i2)
{
    if (i1->s6_addr32[0] == i2->s6_addr32[0] &&
        i1->s6_addr32[1] == i2->s6_addr32[1] &&
        i1->s6_addr32[2] == i2->s6_addr32[2] &&
        i1->s6_addr32[3] == i2->s6_addr32[3])
        return 1;
    return 0;
}

void doubleHashTable(struct t_hashTable *hashTable, int aggkey)
{
    struct t_dataStruct *oldDataStruct = hashTable->data;
    uint32_t oldSize = hashTable->size;
    initHashTable(hashTable, oldSize * 2);

    struct flow tmpFl;

    uint32_t i;
    for (i = 0; i < oldSize; i++)
    {
        if (oldDataStruct[i].used)
        {
            tmpFl.bytes = __builtin_bswap64(oldDataStruct[i].bytes);
            tmpFl.packets = __builtin_bswap64(oldDataStruct[i].packets);
            if (aggkey == EN_AGG_SRCIP4)
            {
                tmpFl.src_addr.s6_addr32[3] = oldDataStruct[i].addr4;
                addRecordIP4(&tmpFl, aggkey, 32, hashTable);
            }
            else if (aggkey == EN_AGG_DSTIP4)
            {
                tmpFl.dst_addr.s6_addr32[3] = oldDataStruct[i].addr4;
                addRecordIP4(&tmpFl, aggkey, 32, hashTable);
            }
            else if (aggkey == EN_AGG_SRCIP6)
            {
                tmpFl.src_addr = oldDataStruct[i].addr6;
                addRecordIP6(&tmpFl, aggkey, 128, hashTable);
            }
            else if (aggkey == EN_AGG_DSTIP6)
            {
                tmpFl.dst_addr = oldDataStruct[i].addr6;
                addRecordIP6(&tmpFl, aggkey, 128, hashTable);
            }
            else if (aggkey == EN_AGG_SRCIP)
            {
                if (oldDataStruct[i].used == EN_DATA_IP4)
                {
                    tmpFl.src_addr.s6_addr32[3] = oldDataStruct[i].addr4;
                    addRecordIP4(&tmpFl, aggkey, 32, hashTable);
                }
                else
                {
                    tmpFl.src_addr = oldDataStruct[i].addr6;
                    addRecordIP6(&tmpFl, aggkey, 128, hashTable);
                }
            }
            else if (aggkey == EN_AGG_DSTIP6)
            {
                if (oldDataStruct[i].used == EN_DATA_IP4)
                {
                    tmpFl.dst_addr.s6_addr32[3] = oldDataStruct[i].addr4;
                    addRecordIP4(&tmpFl, aggkey, 32, hashTable);
                }
                else
                {
                    tmpFl.dst_addr = oldDataStruct[i].addr6;
                    addRecordIP6(&tmpFl, aggkey, 128, hashTable);
                }
            }
            else if (aggkey == EN_AGG_SRCPORT)
            {
                tmpFl.src_port = __builtin_bswap16(oldDataStruct[i].port);
                addRecordPort(&tmpFl, aggkey, hashTable);
            }
            else if (aggkey == EN_AGG_DSTPORT)
            {
                tmpFl.dst_port = __builtin_bswap16(oldDataStruct[i].port);
                addRecordPort(&tmpFl, aggkey, hashTable);
            }
        }
    }
    free(oldDataStruct);
}

uint32_t hashFunction(const uint32_t input, uint32_t tableSize)
{
    return ((uint32_t) (input * 2654435761) % tableSize);
}

uint32_t hashFunction6(const struct in6_addr input, uint32_t tableSize)
{
    return ((uint32_t) (input.s6_addr32[0] +
                        input.s6_addr32[1] +
                        input.s6_addr32[2] +
                        input.s6_addr32[3] *
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

struct in6_addr maskIPv6(struct in6_addr* addr, int mask)
{
    struct in6_addr result;

    if (mask == 128)
    {
        result.s6_addr32[0] = addr->s6_addr32[0];
        result.s6_addr32[1] = addr->s6_addr32[1];
        result.s6_addr32[2] = addr->s6_addr32[2];
        result.s6_addr32[3] = addr->s6_addr32[3];
        return result;
    }

    short blocks = mask / 32;

    int i;
    for (i = 0; i < blocks; i++)
    {
        result.s6_addr32[i] = addr->s6_addr32[i] & masks[32];
    }

    result.s6_addr32[blocks] = addr->s6_addr32[blocks] & masks[mask % 32];
    for (i = blocks + 1; i < 4; i++)
    {
        result.s6_addr32[i] = 0;
    }

    return result;
}

int compareSortStruct(const void * a, const void * b)
{
    if (((struct t_sortStruct*) a)->value < ((struct t_sortStruct*) b)->value)
        return 1;
    else if (((struct t_sortStruct*) a)->value == ((struct t_sortStruct*) b)->value)
        return 0;
    else
        return -1;
}

int sortHashArray(struct t_sortStruct *hashArray, struct t_hashTable *hashTable, int sortkey)
{
    /* Fill the internal sort structure */
    uint32_t n = 0;
    uint32_t i;
    for (i = 0; i < hashTable->size; i++)
    {
        if (hashTable->data[i].used)
        {
            if (sortkey == EN_SORT_BYTES)
                hashArray[n].value = hashTable->data[i].bytes;
            else
                hashArray[n].value = hashTable->data[i].packets;

            hashArray[n].key = i;
            n++;
        }
    }

    /* Sort internal sort structure */
    qsort(hashArray, n, sizeof (struct t_sortStruct), compareSortStruct);

    return n;
}

int processDirectory(char *directory, struct t_hashTable *hashTable, int aggkey, int mask)
{
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(directory)) != NULL)
    {
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

            if (ent->d_type != DT_DIR)
            {
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
                        addRecordIP(&fl, aggkey, mask, hashTable);
                    }
                }
                else
                {
                    while ((n = fread(&fl, sizeof (struct flow), 1, fp)) != 0)
                    {
                        addRecordPort(&fl, aggkey, hashTable);
                    }
                }

                /* Close the file */
                fclose(fp);

                /* Free the file name */
                free(file);
            }
            else
            {
                /* Recursively process directory */
                if (processDirectory(file, hashTable, aggkey, mask) != 0)
                {
                    closedir(dir);
                    return 1;
                }
                free(file);
            }
        }
        closedir(dir);
    }
    else
    {
        /* Unable to open directory */
        printError("Unable to open given directory!");
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char *directory;
    int sortkey;
    int aggkey;
    int mask = 0;
    struct t_hashTable *hashTable = malloc(sizeof (struct t_hashTable));

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

    /* Initialize has tables */
    if (aggkey == EN_AGG_SRCIP ||
        aggkey == EN_AGG_DSTIP ||
        aggkey == EN_AGG_SRCIP4 ||
        aggkey == EN_AGG_DSTIP4 ||
        aggkey == EN_AGG_SRCIP6 ||
        aggkey == EN_AGG_DSTIP6)
    {
        /* Initialize hash table for IP based data structure */
        initHashTable(hashTable, EN_HASH_INIT_IP);
    }
    else
    {
        /* Initialize hash table for port based data structure */
        initHashTable(hashTable, EN_HASH_INIT_PORT);
    }

    /* Process given directory recursively */
    if (processDirectory(directory, hashTable, aggkey, mask) != 0)
    {
        /* Free the hash tables */
        finishHashTable(hashTable);
        printf("pip");
        return (EXIT_FAILURE);
    }

    /* Print header */
    if (aggkey == EN_AGG_SRCIP ||
        aggkey == EN_AGG_SRCIP4 ||
        aggkey == EN_AGG_SRCIP6)
        printf("#srcip,packets,bytes\n");
    else if (aggkey == EN_AGG_DSTIP ||
        aggkey == EN_AGG_DSTIP4 ||
        aggkey == EN_AGG_DSTIP6)
        printf("#dstip,packets,bytes\n");
    else if (aggkey == EN_AGG_SRCPORT)
        printf("#srcport,packets,bytes\n");
    else if (aggkey == EN_AGG_DSTPORT)
        printf("#dstport,packets,bytes\n");

    /* Sort the internal structure */
    if (aggkey == EN_AGG_SRCIP ||
        aggkey == EN_AGG_DSTIP ||
        aggkey == EN_AGG_SRCIP6 ||
        aggkey == EN_AGG_DSTIP6 ||
        aggkey == EN_AGG_SRCIP4 ||
        aggkey == EN_AGG_DSTIP4)
    {
        /* Fill the internal sort structure */
        struct t_sortStruct *hashTableArray = malloc(hashTable->count * sizeof (struct t_sortStruct));
        uint32_t n = sortHashArray(hashTableArray, hashTable, sortkey);

        /* Print the sorted internal structure */
        uint32_t i;
        for (i = 0; i < n; i++)
        {
            printData(&(hashTable->data[hashTableArray[i].key]));
        }

        /* Free the structure */
        free(hashTableArray);
    }
    else
    {
        /* Fill the internal sort structure */
        struct t_sortStruct *hashTableArray = malloc(hashTable->count * sizeof (struct t_sortStruct));
        uint32_t n = sortHashArray(hashTableArray, hashTable, sortkey);

        /* Print the sorted internal structure */
        uint32_t i;
        for (i = 0; i < n; i++)
        {
            printData(&(hashTable->data[hashTableArray[i].key]));
        }

        /* Free the structure */
        free(hashTableArray);
    }

    /* Free the hash tables */
    finishHashTable(hashTable);
    return (EXIT_SUCCESS);
}
