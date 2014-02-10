#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>

#include "main.h"

void print_flow(struct flow *fl) {
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(fl->src_addr), srcip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(fl->dst_addr), dstip, INET6_ADDRSTRLEN);
    fprintf(stdout, "%s:%d -> %s:%d, pkts: %"PRIi64" , bytes: %"PRIi64" \n", srcip, ntohs(fl->src_port), dstip, ntohs(fl->dst_port),
            __builtin_bswap64(fl->packets),
            __builtin_bswap64(fl->bytes));
}

void printHelp(char *name) {
    fprintf(stdout, "Usage: %s -f directory -a aggregation -s sort\n", name);
    fprintf(stdout, "       %s -h\n", name);
    fprintf(stdout, "       %s --help\n", name);
    fprintf(stdout, "    directory    directory with flow data files\n");
    fprintf(stdout, "    aggregation  aggregation key [srcip/mask, dstip/mask, srcport, dstport]\n");
    fprintf(stdout, "    sort         sort key [srcport, dstport, packets, bytes]\n\n");
}

void printError(char *msg) {
    fprintf(stderr, "%s\n", msg);
}

int main(int argc, char *argv[]) {
    int opt;
    char *directory;
    char *sortkey;
    char *aggregationkey;

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        /* Help requested */
        printHelp(argv[0]);
        return (EXIT_SUCCESS);
    }
    else if (argc == 7 && strcmp(argv[1], "-f") == 0 && strcmp(argv[3], "-a") == 0 && strcmp(argv[5], "-s") == 0) {
        /* Correct parameters */
        directory = argv[2];
        sortkey = argv[4];
        aggregationkey = argv[6];
    }
    else {
        /* Invalid parameters! */
        printError("Invalid parameters!");
        printHelp(argv[0]);
        return (EXIT_FAILURE);
    }


    FILE *fp = fopen(directory, "rb");
    struct flow fl;
    size_t n = 0;
    while ((n = fread(&fl, sizeof (struct flow), 1, fp)) != 0) {
        print_flow(&fl);
        break;
    }
    fclose(fp);

    return (EXIT_SUCCESS);
}
