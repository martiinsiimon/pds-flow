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


// prototypes //
void print_flow(struct flow *fl);
void printHelp(char *name);
void printError(char *msg);

#endif /* MAIN_H */