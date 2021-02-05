Programming Exercises
=======================

Setup
------


The code for these exercises originally came from:
> http://cr.yp.to/djbdns/djbdns-1.05.tar.gz

For a quick way to set up a build environment on Debian Linux, follow these instructions:

    # Make sure you have some standard libs and a compiler:
    $ sudo apt-get install make gcc libssl-dev
    
    # Now to compile (but not install) djbdns
    $ git clone <BitBucket git URL>
    $ cd coding-challenge
    $ echo "cc -O2 -include /usr/include/errno.h" > conf-cc
    $ make

    # Rather than setting up a service, you can use our run-script to run it in foreground.
    $ ./run-dnscache.sh
    # You are now running dnscache.  Run make to re-compile with your code changes.
    # Just run ./run-dnscache.sh whenever you want to start it up.
    # You can test by issuing: "dig @127.0.0.1 yahoo.com" from another terminal on the same machine.


Programming Challenges:


1. myip.opendns.com
----------------

The OpenDNS resolvers treat the myip.opendns.com domain name
specially.  They respond to a query for myip.opendns.com with the IP
address of the client that sent the query.  For example, my
development host's IP address address is `67.215.67.199`.  Here's what I
see when I query for `myip.opendns.com`:

    $ dig @208.67.222.222 myip.opendns.com
    
    ; <<>> DiG 9.3.4-P1.2 <<>> @208.67.222.222 myip.opendns.com
    ; (1 server found)
    ;; global options:  printcmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2559
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    
    ;; QUESTION SECTION:
    ;myip.opendns.com.              IN      A
    
    ;; ANSWER SECTION:
    myip.opendns.com.       0       IN      A       67.215.68.199

    ;; Query time: 13 msec
    ;; SERVER: 208.67.222.222#53(208.67.222.222)
    ;; WHEN: Fri May  7 23:25:30 2010
    ;; MSG SIZE  rcvd: 50

Implement this behavior in dnscache.

2. okclient()
----------------

The `okclient()` function (in okclient.c) performs IP address-based
access control for dnscache.  It does so using the `stat()` system call,
the overhead of which can limit the throughput of a busy server.
Modify dnscache to perform IP address-based access control without
using system calls for each DNS request.

3. Cache Delete
-----------------

Modify cache.c to add a method to delete an entry from the cache.

4. New Features
----------------
Modify cache.c, or provide an
entirely new cache.c, to implement some interesting new functionality.
For example, you might provide a way to delete the cache entries for
all subdomains of a domain, or to do distributed caching across a
cluster, or to save and restore the contents of the cache.  Perhaps
there is a better way to structure the contents of the cache in a
hierarchy of sorts.  This is usually the most interesting and fun of
the problems in this challenge;  we know this question is the one we
look forward to seeing the most. If you are short on time we would
still like to see your thoughts on how you'd approach this problem. :-)

