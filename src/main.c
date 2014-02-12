#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <dirent.h>

#include "main.h"

void print_flow(struct flow *fl)
{
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(fl->src_addr), srcip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(fl->dst_addr), dstip, INET6_ADDRSTRLEN);
    fprintf(stdout, "%s:%d -> %s:%d, pkts: %"PRIi64" , bytes: %"PRIi64" \n", srcip, ntohs(fl->src_port), dstip, ntohs(fl->dst_port),
            __builtin_bswap64(fl->packets),
            __builtin_bswap64(fl->bytes));
}

void printHelp(char *name)
{
    fprintf(stdout, "Usage: %s -f directory -a aggregation -s sort\n", name);
    fprintf(stdout, "       %s -h\n", name);
    fprintf(stdout, "       %s --help\n", name);
    fprintf(stdout, "    directory    directory with flow data files\n");
    fprintf(stdout, "    aggregation  aggregation key [srcip/mask, dstip/mask, srcport, dstport]\n");
    fprintf(stdout, "    sort         sort key [srcport, dstport, packets, bytes]\n\n");
}

void printError(char *msg)
{
    fprintf(stderr, "ERR: %s\n", msg);
}

int parseSortKey(char *key)
{
    if (strcmp(key, "srcport") == 0)
        return EN_SORT_SRCPORT;
    else if (strcmp(key, "dstport") == 0)
        return EN_SORT_DSTPORT;
    else if (strcmp(key, "packets") == 0)
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
        //printf("%d", p - key); //FIXME compare with substring, check if position is not behind the end and convert the rest to integer (mask))
        if (strcmp(key, "srcip/mask") == 0)
        {
            *mask = 10; //FIXME
            return EN_AGG_SRCIP;
        }
        else if (strcmp(key, "dstip/mask") == 0)
        {
            *mask = 10; //FIXME
            return EN_AGG_DSTIP;
        }
    }
    else if (strcmp(key, "srcport") == 0)
        return EN_AGG_SRCPORT;
    else if (strcmp(key, "dstport") == 0)
        return EN_AGG_DSTPORT;
    else
        return EN_ERROR;
}

void addRecord(struct flow *fl, int agsign, int mask)
{
    //FIXME
    return;
}

int main(int argc, char *argv[])
{
    char *directory;
    int sortkey;
    int aggkey;
    int mask;

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
        if ((sortkey = parseAggKey(argv[4], &mask)) == EN_ERROR)
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

            // DBG //////////////////////////////////////////////
            //fprintf(stdout, "%s\n", file);
            // ENDDBG ///////////////////////////////////////////

            /* Start to parse file by chosen aggregation */
            FILE *fp = fopen(file, "rb");
            struct flow fl;
            size_t n = 0;
            while ((n = fread(&fl, sizeof (struct flow), 1, fp)) != 0)
            {
                /*TODO*/
                //print_flow(&fl);
                addRecord(&fl, aggkey, mask);
                //break;
            }

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


    /*
        FILE *fp = fopen(directory, "rb");
        struct flow fl;
        size_t n = 0;
        while ((n = fread(&fl, sizeof (struct flow), 1, fp)) != 0) {
            print_flow(&fl);
            break;
        }
        fclose(fp);
     */

    return (EXIT_SUCCESS);
}
