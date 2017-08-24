/*
* Copyright (c) 2014-2017 irql <interruptrequestlevel@gmail.com>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define MAX_ADDR_LEN 15
#define MAX_THREADS 100 // Arbitrary number, may need to calculate in the future...

#define PAD_CLOCKITEM 13
#define PAD_THREADITEM 6
#define PAD_ADDRITEM MAX_ADDR_LEN

#define _NADDR(x) x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff
#define _HADDR(x) (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff

#define _SPIN_START(y) while(y); \
    y = 1;
#define _SPIN_END(y) y = 0;

struct cidr
{
    unsigned int ipnum;
    unsigned int nthreads;
    unsigned int checked;
    unsigned int resolve;

    in_addr_t first;
    in_addr_t last;

    unsigned int days;
    unsigned int hours;
    unsigned int minutes;
    unsigned int seconds;

    int lock;
    int silent;
};

struct thread_args
{
    struct cidr *scan_data;
    in_addr_t first;
    in_addr_t last;
    FILE *fp;
    int log;
};

void print_usage(char *name)
{
    printf( "Usage: %1$s [-q] cidr/range [logfile]\n"
            "Options:\n"
            "\t-q Do not print addresses/hostnames\n"
            "Ex:\n"
            "\t%1$s 192.168.0.0/24\n"
            "\t%1$s 192.168.0.0/24 log.txt\n"
            "\t%1$s 192.168.0.1-192.168.0.254\n"
            "\t%1$s -q 192.168.0.0/24\n",
            name);
    exit(0);
}

struct cidr *cidr_format(char *inetnum)
{
    static struct cidr ret;
    in_addr_t ipaddr;
    char *fmt;
    int num;

    memset(&ret, 0, sizeof(struct cidr));

    if((fmt = strchr(inetnum, '/')) == 0)
        return 0;

    num = atoi(fmt + 1);
    if(num < 1 || num > 30)
        return 0;

    *fmt = 0;

    if(inet_pton(AF_INET, inetnum, &ipaddr) != 1)
        return 0;

    ret.ipnum = (0xffffffff >> num);
    ret.last = (ntohl(ipaddr) | ret.ipnum) - 1;
    ret.first = ret.last - ret.ipnum + 2;

    ret.first = htonl(ret.first);
    ret.last = htonl(ret.last);

    return &ret;
}

struct cidr *range_format(char *inetnum)
{
    static struct cidr ret;
    char *fmt;
    int num;

    memset(&ret, 0, sizeof(struct cidr));

    if((fmt = strchr(inetnum, '-')) == 0)
        return 0;

    if(inet_pton(AF_INET, fmt + 1, &ret.last) != 1)
        return 0;

    *fmt = 0;

    if(inet_pton(AF_INET, inetnum, &ret.first) != 1)
        return 0;

    if((ret.ipnum = ntohl(ret.last) - ntohl(ret.first)) < 0)
        return 0;

    return &ret;
}

void clock_thread(struct cidr *scan_data)
{
    do
    {
        if(scan_data->seconds == 59)
        {
            scan_data->minutes++;
            scan_data->seconds = -1;
        }
        if(scan_data->minutes == 59)
        {
            scan_data->hours++;
            scan_data->minutes = 0;
        }
        if(scan_data->hours == 23)
        {
            scan_data->days++;
            scan_data->hours = 0;
        }

        scan_data->seconds++;
    }
    while(!sleep(1));
}

void update_interface(in_addr_t ipaddr, struct cidr *scan_data)
{
    _SPIN_START(scan_data->lock);

    if(scan_data->silent)
    {
        char saddr[MAX_ADDR_LEN + 1];
        int len;
        
        memset(saddr, 0, sizeof(saddr));
        snprintf(saddr, MAX_ADDR_LEN, "%i.%i.%i.%i", _HADDR(ipaddr));
        len = strlen(saddr);
        memset(saddr + len, ' ', MAX_ADDR_LEN - len);

        fprintf(stderr, "\033[K%02i:%02i:%02i:%02i [%3i] %s %i(%i resolve)/%i\r",
            scan_data->days, scan_data->hours, scan_data->minutes, scan_data->seconds,
            scan_data->nthreads, saddr,
            scan_data->checked, scan_data->resolve, scan_data->ipnum);
    }
    else
    {
        fprintf(stderr, "\033[s\033[0;0H\033[K%02i:%02i:%02i:%02i [%3i] %i.%i.%i.%i\033[0;%iH%i(%i resolve)/%i\033[u",
            scan_data->days, scan_data->hours, scan_data->minutes, scan_data->seconds,
            scan_data->nthreads, _HADDR(ipaddr), PAD_ADDRITEM + PAD_THREADITEM + PAD_CLOCKITEM + 1,
            scan_data->checked, scan_data->resolve, scan_data->ipnum);
    }

    _SPIN_END(scan_data->lock);
}

void scan_thread(struct thread_args *arg)
{
    struct sockaddr_in scan_struct;
    char dnsname[NI_MAXHOST + 1];
    char servname[NI_MAXSERV + 1];
    in_addr_t test = arg->first;

    memset(&scan_struct, 0, sizeof(scan_struct));
    scan_struct.sin_family = AF_INET;

    do
    {
        arg->scan_data->checked++;
        if((test & 0xff) == 0 || (test & 0xff) == 255) continue;

        scan_struct.sin_addr.s_addr = htonl(test);

        int result = getnameinfo(
            (struct sockaddr *)&scan_struct,
            sizeof(struct sockaddr_in),
            dnsname,
            NI_MAXHOST,
            servname,
            NI_MAXSERV,
            NI_DGRAM | NI_NAMEREQD
        );

        char cip[MAX_ADDR_LEN + 1];
        snprintf(cip, MAX_ADDR_LEN, "%i.%i.%i.%i", _HADDR(test));

        switch(result) {
        case EAI_AGAIN:
            fprintf(stderr, "%s: could not be resolved at this time.\n", cip);
            break;
        case EAI_BADFLAGS:
            fprintf(stderr, "%s: Bad flags\n", cip);
            break;
        case EAI_FAIL:
            fprintf(stderr, "%s: Failure occured\n", cip);
            break;
        case EAI_FAMILY:
            fprintf(stderr, "%s: Address family not recognized\n", cip);
            break;
        case EAI_MEMORY:
            fprintf(stderr, "%s: OUT OF MEMORY!\n", cip);
            break;
        case EAI_NONAME:
            //fprintf(stderr, "%s: No hostname found\n", cip);
            break;
        case EAI_OVERFLOW:
            fprintf(stderr, "%s: Host or serv name buffer too small\n", cip);
            break;
        case EAI_SYSTEM:
            fprintf(stderr, "%s: A system error occured: %d\n", cip, errno);
            break;
        default:
        {
            int i;

            if(!arg->scan_data->silent)
            {
                i = PAD_ADDRITEM - strlen(cip);

                _SPIN_START(arg->scan_data->lock);
                fprintf(stderr, "%s\033[%iC \t%s, %s\n", cip, i, dnsname, servname);
                _SPIN_END(arg->scan_data->lock);
            }

            arg->scan_data->resolve++;

            if(arg->log)
                fprintf(arg->fp, "%i.%i.%i.%i \t%s\n",
                    _HADDR(test), dnsname);
        }
        }

        update_interface(test, arg->scan_data);
    }
    while(++test != arg->last);

    arg->scan_data->nthreads--;

    pthread_exit(0);
}

int main(int argc, char **argv)
{
    struct cidr *scan_data;
    FILE *fp;
    int start = 1,
        opt_log = 0,
        opt_silent = 0;

    pthread_t clock;
    pthread_t threads[MAX_THREADS];
    struct thread_args args[MAX_THREADS];
    unsigned int tnum, i;

    if(argc < 2)
        print_usage(*argv);

    if(strcmp(argv[1], "-q") == 0)
    {
        opt_silent = 1;
        start++;
    }

    if((scan_data = cidr_format(argv[start])) == 0)
        if((scan_data = range_format(argv[start])) == 0)
            print_usage(*argv);

    if((argc - start) == 2)
    {
        if((fp = fopen(argv[start + 1], "w")) == 0)
        {
            fputs("Failed to open log file for writing\n", stderr);
            return 1;
        }

        opt_log = 1;
    }

    scan_data->first = ntohl(scan_data->first);
    scan_data->last = ntohl(scan_data->last);
    scan_data->silent = opt_silent;

    if(!scan_data->silent)
        fputs("\033[2J\033[0;0HStarting scan...\n", stderr);

    // World's worst allocating algorithm
    // First, see if the IP number can possibly be a power of two
    for(i = 8; i < 30; i++)
    {
        int j = i - 1;
        for(tnum = 2; j--; tnum *= 2);
        if(tnum > scan_data->ipnum + 1)
            break;
        if(tnum == scan_data->ipnum + 1 || tnum == scan_data->ipnum - 1)
        {
            scan_data->ipnum = tnum;
            break;
        }
    }

    // Attempt to find an optimum number of threads (how we can split up ipnum equally)
    for(tnum = MAX_THREADS; (scan_data->ipnum % tnum) != 0 && tnum > 0; tnum--);

    // Or else, f**k it
    // In other words, if the ridiculous number it came up with is going to be outside the
    // intended number of IPs we wish to RDNS by a margin of 5%, JUST USE MAX_THREADS
    // BECAUSE ITS YOUR FAULT FOR PICKING A S***TY RANGE
    if(((scan_data->ipnum / tnum)*tnum < (scan_data->ipnum - (scan_data->ipnum/20))) ||
        ((scan_data->ipnum / tnum)*tnum > (scan_data->ipnum + (scan_data->ipnum/20))))
        tnum = MAX_THREADS;

    if(scan_data->silent)
        fprintf(stderr, "Using %i threads with %i IPs per thread (will check %i/%i)\n",
            tnum, scan_data->ipnum / tnum, (scan_data->ipnum / tnum)*tnum, scan_data->ipnum);

    scan_data->nthreads = tnum;

    // Start all the threads
    for(i = 0; i < tnum; i++)
    {
        memset(&args[i], 0, sizeof(struct thread_args));

        args[i].scan_data = scan_data;
        args[i].first = scan_data->first + i*(scan_data->ipnum / tnum);
        args[i].last = scan_data->first + (i + 1)*(scan_data->ipnum / tnum);
        args[i].fp = fp;
        args[i].log = opt_log;

        pthread_create(&threads[i], 0, (void * (*)(void *))scan_thread, &args[i]);
    }

    pthread_create(&clock, 0, (void * (*)(void *))clock_thread, scan_data);

    // Sit back and wait
    for(i = 0; i < tnum; i++)
        pthread_join(threads[i], 0);

    pthread_cancel(clock);

    if(scan_data->silent) putc('\n', stderr);

    if(opt_log)
    {
        fprintf(fp, "Scan complete in %i Days, %i Hours, %i Minutes and %i Seconds! %i resolved out of %i checked",
            scan_data->days, scan_data->hours, scan_data->minutes, scan_data->seconds, scan_data->resolve, scan_data->checked);
        fclose(fp);
    }

    return 0;
}
