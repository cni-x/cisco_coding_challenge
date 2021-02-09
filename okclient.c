#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "ip4.h"
#include "okclient.h"

#include "stdio.h"
#include "buffer.h"
#include "uint32.h"
#include "uint16.h"
#include "byte.h"
#include "log.h"

static char fn[3 + IP4_FMT];


#define AVL_IP 0x7f000000
#define AVL_MASK 0xffffffc0

static void string(const char *s)
{
  buffer_puts(buffer_2,s);
}

#define number(x) ( (u64 = (x)), u64_print() )
static uint64 u64;
static void u64_print(void)
{
  char buf[20];
  unsigned int pos;

  pos = sizeof buf;
  do {
    if (!pos) break;
    buf[--pos] = '0' + (u64 % 10);
    u64 /= 10;
  } while(u64);

  buffer_put(buffer_2,buf + pos,sizeof buf - pos);
}

// handles challenge 2
int okclient_ip_based(char ip[4]) {
  uint32 x;
  uint32_unpack_big(ip, &x);
  number(x);
  string("\n");
  if ((x & AVL_MASK) == AVL_IP) return 1;
  return 0;
}

int okclient(char ip[4])
{
  struct stat st;
  int i;

  fn[0] = 'i';
  fn[1] = 'p';
  fn[2] = '/';
  fn[3 + ip4_fmt(fn + 3,ip)] = 0;

  for (;;) {
    string(fn); string(" ");
    if (stat(fn,&st) == 0) return 1;
    /* treat temporary error as rejection */
    i = str_rchr(fn,'.');
    if (!fn[i]) return 0;
    fn[i] = 0;
  }

}
