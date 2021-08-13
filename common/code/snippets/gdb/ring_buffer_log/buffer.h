typedef struct ring_buffer
{
    char *data;
    volatile uint32_t read;
    volatile uint32_t write;
    uint32_t mask; // size of the array pointed to by data, which is a positive power of two.
} ring_buffer;
