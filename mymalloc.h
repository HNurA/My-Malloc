/*TIPLER VE TANIMLAMALARDA DEGISIKLIK YAPMAYINIZ:
HATA OlDUGUNU DUSUNUYORSANIZ PIAZZADAN FOLLOW-UPLARDA PAYLASINIZ
*/
#include <inttypes.h>
#include <stddef.h>
#define HEAP_SIZE 1024 /*used in sbrk to extend heap*/

typedef enum { BEST_FIT, NEXT_FIT, FIRST_FIT, WORST_FIT } Strategy;
typedef enum { ADDR_ORDERED_LIST, UNORDERED_LIST } ListType;
Strategy strategy = BEST_FIT;
ListType listtype = ADDR_ORDERED_LIST;

/* There is a padding:|8-byte size|4 byte isfree|padding|*/
typedef struct tag {
    uint64_t size;       /*number of  16 byte blocks*/
    uint32_t isfree;     /* you can make this larger and remove padding: */
    uint32_t padding; /*unused space between boundaries*/
} __attribute__((packed, aligned(16))) Tag; 

/*Block: |8byte(next)|8byte(prev)|8-byte size|4byte isfree|padding|0-byte(data)|*/
typedef struct block {
    struct block *next; /*next free*/
    struct block *prev; /*next free*/
    Tag info;           /*size and isfree*/
    char data[];        /*start of the allocated memory*/
} __attribute__((packed, aligned(16))) Block;

static Block *free_list = 0;  /*start of the free list*/
static Block *heap_start = 0; /*head of allocated memory from sbrk */

/*end of allocated memory from sbrk: the end block can be extended */
static Block *heap_end = 0;

/*in LIFO equal to *free_list,
in address ordered it is different*/
static Block *last_freed = 0;

void *mymalloc(size_t size);
void myfree(void *p);

Block *split_block(Block *b, size_t size);
Block *left_coalesce(Block *b);
Block *right_coalesce(Block *b);
Block *next_block_in_freelist(Block *b);
Block *next_block_in_addr(Block *b);
Block *prev_block_in_freelist(Block *b);
Block *prev_block_in_addr(Block *b);
/**for a given size in bytes, returns number of 16 blocks*/
uint64_t numberof16blocks(size_t size_inbytes);
/* prints heap*/
void printheap();
ListType getlisttype();
int setlisttype(ListType listtype);
Strategy getstrategy();
int setstrategy(Strategy strategy);
