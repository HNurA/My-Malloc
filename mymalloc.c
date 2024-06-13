/**Bu dosya C programları için memory allocator yapmaktadır.
* last update: 27.04.2024
* authors: Begüm Karabaş 22120205002
*          Hilal Nur Albayrak 22120205056
*/

#include "mymalloc.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#define MAX_BLOCKS 100 /* Maksimum blok sayısı*/

size_t block_sizes[MAX_BLOCKS]; /* Global blok boyutları dizisi*/
int block_isfree[MAX_BLOCKS];   /* Global blok isfree değerleri dizisi*/
size_t block_count = 0; /* Oluşturulan blok sayısı*/
size_t counter = 0;

/*fonksiyon prototipleri*/
void add_block_info(size_t size, int isfree);
void add_to_free_list(void *new_memory, size_t size);
void *expand_heap(size_t size);


/**Bu fonksiyon, istenen boyutta bir bellek bloğu tahsis 
* etmek için kullanılır ve bellek tahsisi işlemi için farklı stratejiler kullanır
*/
void *mymalloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    /*16'ya yuvarlanmış boyutu hesapla*/
    size_t rounded_size = ((size + 15) / 16) * 16;

    uint64_t num_blocks = numberof16blocks(size);

    add_block_info(rounded_size, 0);

    /*İlk defa çağrılıyorsa veya yeterli alan yoksa heap alanı genişlet*/
    if (heap_start == NULL || heap_end == NULL) {
        heap_start = sbrk(HEAP_SIZE);
        if (heap_start == (void*)-1) {
            return NULL; 
        }
        heap_end = heap_start + HEAP_SIZE;
        free_list = heap_start;
        free_list->info.size = HEAP_SIZE / 16;
        free_list->info.isfree = 1;
        free_list->next = free_list->prev = NULL;
    }
    
    Block *free_block = NULL;
    Block *split_block_address = NULL;
    Block *current = NULL;

    if (getstrategy() == BEST_FIT) {
        /*En uygun bloğu bulmak için serbest blokları dolaş*/
        Block *current_block = free_list;
        Block *best_fit_block = NULL;
        uint64_t min_remaining_blocks = UINT64_MAX; /*Başlangıçta çok büyük bir değer atıyoruz*/

        while (current_block != NULL) {
            if (current_block->info.size >= num_blocks) {
                /**Blok, istenen boyuttan büyük veya eşitse ve en küçük kalıntıya 
                * sahipse, en uygun bloğu güncelle
                */
                uint64_t remaining_blocks = current_block->info.size - num_blocks;
                if (remaining_blocks < min_remaining_blocks) {
                    min_remaining_blocks = remaining_blocks;
                    best_fit_block = current_block;
                }
            }
            current_block = current_block->next;
        }

        if (best_fit_block != NULL) {
            free_block = best_fit_block;
        }
        current = current_block;

    } else if (getstrategy() == NEXT_FIT) {
        /*Serbest blokları dolaşarak uygun bloğu bul*/
        Block *current_block = last_freed;
        while (current_block != NULL) {
            if (current_block->info.size >= num_blocks) {
                free_block = current_block;
                break;
            }
            current_block = next_block_in_addr(current_block);
            /*Serbest blokları dolaşırken last_freed'e ulaşırsak tekrar başa dön*/
            if (current_block == last_freed) {
                break;
            }
        }

        current = current_block;

    } else if (getstrategy() == FIRST_FIT) {
        Block *current_block = free_list;
        while (current_block != NULL) {
            if (current_block->info.size >= num_blocks) {
                free_block = current_block;
                break;
            }
            current_block = next_block_in_addr(current_block);
        }
        current = current_block;

    } else if (getstrategy() == WORST_FIT) {
        /*Serbest blokları dolaşarak uygun bloğu bul*/
        Block *current_block = free_list;
        Block *worst_fit_block = NULL;
        uint64_t max_remaining_blocks = 0; /*Başlangıçta çok küçük bir değer atıyoruz*/

        while (current_block != NULL) {
            if (current_block->info.size >= num_blocks) {
                /**Blok, istenen boyuttan büyük veya eşitse ve en büyük 
                * kalıntıya sahipse, en kötü uygun bloğu güncelle
                */
                uint64_t remaining_blocks = current_block->info.size - num_blocks;
                if (remaining_blocks > max_remaining_blocks) {
                    max_remaining_blocks = remaining_blocks;
                    worst_fit_block = current_block;
                }
            }
            current_block = next_block_in_addr(current_block);
        }

        /*En kötü uygun bloğu bulduysak, döndürelim*/
        if (worst_fit_block != NULL) {
            free_block = worst_fit_block;
        }
        current = current_block;
    }

    /*Uygun blok bulunamazsa heap i genişlet*/
    if (current == NULL) {

        void *new_memory = expand_heap(rounded_size);
        if (new_memory == NULL) {
            return NULL;  
        }
        current= (Block *)new_memory;
    }

    /*Blok bölünüyorsa fonksiyonu çağır*/
    if (current->info.size > rounded_size) {
        Block *new_block = split_block(current, rounded_size);
        if (new_block == NULL) {
            return NULL;
        }
        current = new_block;
    }

    /*Bloğun durumunu güncelle*/
    current->info.isfree = 0;

    /*Bloğu free listesinden çıkar*/
    if (current == free_list) {
        free_list = current->next;
    }
    if (current->prev != NULL) {
        current->prev->next = current->next;
    }
    if (current->next != NULL) {
        current->next->prev = current->prev;
    }

    return current->data;
}

/** Gönderilen bloğu istenilen size a göre bölen fonksiyon
*/
Block *split_block(Block *b, size_t size) {
    /*Yeni bloğu oluştur*/
    Block *new_block = (Block*)((char*)b + sizeof(Block) + size);
    new_block->info.size = b->info.size - (size + sizeof(Block));
    new_block->info.isfree = 1;
    new_block->next = b->next;
    new_block->prev = b;
    if (b->next != NULL) {
        b->next->prev = new_block;
    }
    b->next = new_block;
    b->info.size = size;

    /*Yeni bloğu free listesine ekle*/
    new_block->next = free_list;
    new_block->prev = NULL;
    if (free_list != NULL) {
        free_list->prev = new_block;
    }
    free_list = new_block;

    return new_block;
}

/**Gönderilen adresteki blocku free leyen fonksiyon
*/
void myfree(void *p) {
    if (p == NULL) {
        return;
    }

    Block *block = (Block*)((char*)p - offsetof(Block, data));
    block->info.isfree = 1;

    /*Bir önceki blok ile birleştir*/
    Block *prev_block = left_coalesce(block);
    /*Bir sonraki blok ile birleştir*/
    Block *next_block = right_coalesce(prev_block);

    /*Serbest bloğu listeye ekle*/
    if (free_list != NULL) {
        free_list->prev = next_block;
    }
    next_block->next = free_list;
    next_block->prev = NULL;
    free_list = next_block;

    counter++ ;
    /*Serbest bırakılan bloğun isfree değerini global diziye güncelle*/
    for (int i = 0; i < counter; ++i) {
        block_isfree[i] = 1;
    }
}

/**Gönderilen block bilgilerini diziye ekleyen fonksiyon
*/
void add_block_info(size_t size, int isfree) {
    if (block_count < MAX_BLOCKS) {
        block_sizes[block_count] = size;
        block_isfree[block_count] = isfree;
        block_count = block_count + 1;
    } else {
        printf("Maksimum blok sayisina ulasildi!\n");
    }
}

/**Belirtilen bellek bloğunu serbest blok listesine ekleyen ve bloğun 
* bilgilerini güncelleyen fonksiyon
*/
void add_to_free_list(void *new_memory, size_t size) {
    Block *new_block = (Block *)new_memory;
    new_block->info.size = size / 16; 
    new_block->info.isfree = 1; 
    new_block->next = free_list; /*Serbest blok listesinin başına ekle*/
    new_block->prev = NULL; /*Yeni eklenen bloğun önceki bloğu yok*/
    if (free_list != NULL) {
        free_list->prev = new_block;
    }
    free_list = new_block; /*Yeni bloğu serbest blok listesinin başı yap*/
}

/** Çağrıldığında heap i genişleten fonksiyon
*/
void *expand_heap(size_t size) {
    void *current_brk = sbrk(0);

    if (sbrk(size) == (void *)-1) {
        return NULL; 
    }

    void *new_memory = current_brk;
    add_to_free_list(new_memory, size);

    return new_memory;
}

/** Gönderilen block u sol blockla birleştiren fonksiyon
*/
Block *left_coalesce(Block *b) {
    /* Sol komşu boşsa, birleştir */
    Block *prev_block = b->prev;
    if (prev_block != NULL && prev_block->info.isfree) {
        prev_block->info.size += sizeof(Block) + b->info.size;
        prev_block->next = b->next;
        if (b->next != NULL) {
            b->next->prev = prev_block;
        }
        return prev_block;
    }
    return b;
}

/** Gönderilen block u sağ blockla birleştiren fonksiyon
*/
Block *right_coalesce(Block *b) {
    /* Sağ komşu boşsa, birleştir */
    Block *next_block = b->next;
    if (next_block != NULL && next_block->info.isfree) {
        b->info.size += sizeof(Block) + next_block->info.size;
        b->next = next_block->next;
        if (next_block->next != NULL) {
            next_block->next->prev = b;
        }
    }
    return b;
}

/*Boş liste için bir sonraki bloğu alan fonksiyon*/
Block *next_block_in_freelist(Block *b){
    return b->next;
}

/*Boş liste için bir önceki bloğu alan fonksiyon*/
Block *prev_block_in_freelist(Block *b){
    return b->prev;
}

/*Adreste bir sonraki bloğu alan fonksiyon*/
Block *next_block_in_addr(Block *b){
    /* Bir sonraki bloğun adresini hesapla */
    return (Block *)((char *)b + b->info.size * 16);
}

/*Adreste bir önceki bloğu alma fonksiyonu*/
Block *prev_block_in_addr(Block *b){
    /* Önceki bloğun adresini hesapla */
    return (Block *)((char *)b - prev_block_in_addr(b)->info.size * 16);
}

/**verilen size miktarı için kaç tane block gerektiğini
* döndüren fonksiyon
*/
uint64_t numberof16blocks(size_t size_inbytes) { 
    uint64_t block_number = 0;
    if (size_inbytes % 16 == 0) {
        block_number = size_inbytes / 16;
    } else {
        block_number = (size_inbytes / 16) + 1;
    }
    return block_number; 
}

/**heap deki block bilgilerini yazdıran fonksiyon 
*/
void printheap() {
    printf("Blocks:\n");
    for (int i = 0; i < block_count; ++i) {
        printf("Size: %lu\nFree: %d\n", block_sizes[i] , block_isfree[i]);
        printf("---------------\n");
    }
}

/**liste tipini döndüren fonksiyon
*/
ListType getlisttype() {
    return listtype;
}

/**liste tipini set etmek için kullanılan fonksiyon
*/
int setlisttype(ListType listtype) {
    return 0;
}

/**strateji tipini döndüren fonksiyon
*/
Strategy getstrategy() {
    return strategy;
}

/**strateji tipini set etmek için kullanılan fonksiyon
*/
int setstrategy(Strategy strategy) {
    return 0;
}

/*Projenin main fonksiyonu
*/
int main() {

    /* Bellek tahsisi yap */
    printf("Allocating memory...\n");
    void *ptr1 = mymalloc(128);
    void *ptr2 = mymalloc(64);
    void *ptr3 = mymalloc(192);
    void *ptr4 = mymalloc(128);

    /* Heap bilgilerini yazdır */
    printheap();

    /* Bellek serbest bırak */
    printf("\nFreeing memory...\n");
    myfree(ptr1);
    myfree(ptr2);
    myfree(ptr3);
    myfree(ptr4);

    /* Heap bilgilerini yazdır */
    printheap();

    return 0;
}
