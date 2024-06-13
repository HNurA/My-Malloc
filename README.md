[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/WRUASzcM)


# BIL 222 Project2: Memory Allocator


## Bilinmesi gerekenler



* Dynamic memory allocation
* sbrk()
* Linked lists
* struct, typedef
* Memory alignment
* Heap


## Özet

Bu ödevde bir tane C programları için memory allocator yapmanız istenmektedir.


## Detay


### Kodlama

Mymalloc.c içerisinde verilen fonksiyonların hepsini implement etmeniz ve özellikle aşağıdaki mymmaloc() ve myfree() fonksiyonalitesini sağlamanız beklenmektedir.

**void *mymalloc(size_t size) **şu şekilde çalışmalıdır.



* Eğer ilk defa çağrılıyorsa yada yeterli alan yoksa, 
    * sbrk kullanılarak HEAP_SIZE byte miktarinda heap alanı genişletilmeli 
    * ve bir tane free block oluşturulmalı
    * Ve free liste eklenmeli
* size  16 nın katı olacak şekilde yukarı yuvarlama yapılmalı
    * Size bilgisi 16nın katı cinsinden
* İstenilen alanı karşılayacak bir tane free block bulunup (seçilen stratejiye göre), bu alan iki bloğa split edilerek **(split fonksiyonunu implement etmeniz gerekiyor)**, birisi free liste eklenmeli diğerinin (**size** kadar alanın)  başlangıç adresi (data[]) return edilmelidir.

**void *myfree(void *p) **



* p ile verilen alan free edilerek free liste eklenmelidir.
* Eğer coalescing(birleştirme) yapılabiliyorsa (bir önceki ve bir sonraki blokla) yapılmalıdır. 
* Free list `listtype` a göre iki tür olabilmektedir: Address bilgisine göre sıralı veya lifo

**void printheap()**

Heap deki blokların metadatalarını tek tek yazdırmalı (dolu yada boş fark etmiyor). 

Yazdırırken çıktı şu formatta olmalı:

Blocks

Free: 1

Size: xxx  

---------------

Free: 0

Size: xxx  

---------------


### Rapor

Programınızı farklı inputlarla çalıştırarak external fragmentationın hangi stratejide daha iyi hangisinde daha kötü olduğunun çok kısa açıklamasını Rapor.txt içerisinde ekleyiniz. 

**<span style="text-decoration:underline;">Bu ödev için verilen mymalloc.h header dosyasını ve orada tanımlı structları kullanmanız zorunludur. </span>**


## Derecelendirme (degistirilebilir)

**-50 Sirali liste veya normal listelerden birinin olmamasi**

%60 mymalloc:



* +5 sbrk ilk defa çağrılması ve tek bloğun başarılı bir şekilde oluşturulması
* **-5 Blok büyüklüğünün 16’nın katı olmaması**
* +40 Free bloğun link list de doğru bir şekilde bulunması
    * +10 First fit
    * +10 Worst fit
    * +10 Best fit
    * +10 Next fit
* +10 Bulunan alanın split edilmesi **(split fonksiyonu)**
* +5 Link listen çıkarılıp return

%30 myfree 



* +10 Link liste başarılı bir şekilde eklenmesi
* +20 Coalescing
    * +10 Next blok ile
    * +10 previous blok ile
    * -10 link listin edit edilmemesi

%10 printheap ve Rapor.txt kodu



* +5 print
* +5 fragmentation açıklama 

-10 puana kadar indentation, dosya isimleri, ve diğer kodlama standartları
Gerekli goruldugunde her hatadan, hata buyuklugune gore -puan.
