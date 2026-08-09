#pragma once

// ===== Consolidated header: VHPcapNg.h =====
// Merges: vh_types, vh_special, vh_debug, vh_null_compression, vh_zstd_compression, vh_compression_functions, vh_compression, vh_file, vh_internal, vh_platform, vh_pcapng, vh_pcapng_ext, vh_util
// Vendored vh_pcapng library (pcapng file I/O), auto-consolidated
// for file-count reduction. Functionality unchanged.

// Original vh_compression.h picked a compression backend via
// #define + #include occurring back-to-back at the same point in the
// file; now that all backends are inlined unconditionally above their
// use, that selection has to happen before any of them, up front here
// (this project never defines USE_Z_STD, so the null backend is what
// was actually being built before this consolidation too).
#if !defined(USE_Z_STD) && !defined(USE_THIS_COMPRESSION_INSTEAD)
#define USE_NULL_COMPRESSION
#endif


// ---- begin vh_types.h ----

typedef enum {
	VH_FALSE = 0,
	VH_TRUE = 1,
//	VH_MAYBE = 2,
} vh_boolean;

typedef enum {
	VH_INFO_TYPE = 0,
	VH_INFO_LENGTH = 1,
	VH_INFO_BODY = 2,
	VH_INFO_OPTIONS = 3,
	VH_INFO_MAX = 4,
} vh_info;

// ---- end vh_types.h ----

// ---- begin vh_special.h ----


#include <stddef.h>
#include <stdint.h>

#ifndef NULL
#define NULL   ((void *) 0)
#endif

struct _vh_section_header {
	uint32_t byteorder_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
};

struct _vh_interface_description_block {
	uint16_t link_type;
	uint16_t reserved;
	uint32_t snapshot_length;
};

struct _vh_enhanced_packet_block {
	uint32_t interface_id;
	uint32_t timestamp_high, timestamp_low;
	uint32_t capture_packet_length;
	uint32_t original_capture_length;
	uint32_t packet_data[0];
};

struct _vh_simple_packet_block {
	uint32_t original_packet_length;
	uint32_t packet_data[0];
};

struct _vh_custom_nonstandard_block {
	uint32_t data_length;
	uint32_t reserved0, reserved1;
	uint32_t packet_data[0];
};


// ---- end vh_special.h ----

// ---- begin vh_debug.h ----


#include <stdio.h>

#ifdef _LIGHT_DEBUG_MODE
#define vh_stop          getchar()
#define DPRINT_HERE(symbol) fprintf(stderr, "%s::%s::%d, %s\n", __FILE__, __FUNCTION__, __LINE__, #symbol)
#else
#define vh_stop          (void)0
#define DPRINT_HERE(symbol) (void)#symbol
#endif

// XXX: Warning: I should not use these macros with functions!!! Undefined for Release.

#define DCHECK_INT(x, y, other)	do { \
		int x_ret = (int)(x); \
		int y_ret = (int)(y); \
		if (x_ret <= y_ret) { \
			fprintf(stderr, "ERROR at %s::%s::%d: %d <= %d\n", \
					__FILE__, __FUNCTION__, __LINE__, x_ret, y_ret); \
			other; \
		} \
	} while (0)

#define DCHECK_ASSERT(x, y, other)	do { \
		int x_ret = (int)(x); \
		int y_ret = (int)(y); \
		if (x_ret != y_ret) { \
			fprintf(stderr, "ERROR at %s::%s::%d: %d != %d\n", \
					__FILE__, __FUNCTION__, __LINE__, x_ret, y_ret); \
			other; \
		} \
	} while (0)

#define DCHECK_ASSERT_EXP(expression, err_message, other) do { \
		if (!(expression)) {\
			fprintf(stderr, "ERROR at %s::%s::%d: %s\n", \
					__FILE__, __FUNCTION__, __LINE__, err_message); \
			other; \
		} \
	} while (0)

#define DCHECK_NULLP(x, other)	do { \
		void *x_ret = (void *)(x); \
		if (x_ret == NULL) { \
			fprintf(stderr, "NULL pointer ERROR at %s::%s::%d\n", \
					__FILE__, __FUNCTION__, __LINE__); \
			other; \
		} \
	} while (0)

#define PCAPNG_WARNING(symbol) fprintf(stderr, "Warning at: %s::%s::%d, %s\n", __FILE__, __FUNCTION__, __LINE__, #symbol)
#define PCAPNG_ERROR(symbol)   fprintf(stderr, "Error at: %s::%s::%d, %s\n", __FILE__, __FUNCTION__, __LINE__, #symbol)

#ifdef  _MSC_VER
#define __attribute__(x)
#endif //  _MSC_VER

#define PCAPNG_ATTRIBUTE_SLOW __attribute__((warning ("slow for large traces")))
#define PCAPNG_ATTRIBUTE_DEPRECATED __attribute__((warning ("deprecated function")))
#define PCAPNG_ATTRIBUTE_UNTESTED __attribute__((warning ("unit test required")))
#define PCAPNG_ATTRIBUTE_REFACTOR __attribute__((warning ("should be refactored")))


// ---- end vh_debug.h ----

// ---- begin vh_null_compression.h ----

#if defined(USE_NULL_COMPRESSION)

#include <stdlib.h>

typedef void _compression_t;
typedef void _decompression_t;

struct vh_file_t;

#endif

// ---- end vh_null_compression.h ----

// ---- begin vh_zstd_compression.h ----
#if defined(USE_Z_STD)

#include <stdint.h>
#include <zstd.h>      // presumes zstd library is installed


//An ethernet packet should only ever be up to 1500 bytes + some header crap
//We also expect some ovehead for the pcapng blocks which contain the ethernet packets
//so allocate 1700 bytes as the max input size we expect in a single shot
#define COMPRESSION_BUFFER_IN_MAX_SIZE 1700

//This is the z-std compression type I would call it z-std type and realias
//2x but compiler won't let me do that across bounds it seems
//So I gave it a generic "light" name....
struct zstd_compression_t
{
	uint32_t* buffer_in;
	uint32_t* buffer_out;
	size_t buffer_in_max_size;
	size_t buffer_out_max_size;
	int compression_level;
	ZSTD_CCtx* cctx;
};

struct zstd_decompression_t
{
	uint32_t* buffer_in;
	uint32_t* buffer_out;
	size_t buffer_in_max_size;
	size_t buffer_out_max_size;
	ZSTD_DCtx* dctx;
	int outputReady;
	ZSTD_outBuffer output;
	ZSTD_inBuffer input;
};


typedef struct zstd_compression_t _compression_t;
typedef struct zstd_decompression_t _decompression_t;

struct vh_file_t;

_compression_t * get_zstd_compression_context(int compression_level);
void free_zstd_compression_context(_compression_t* context);

_decompression_t * get_zstd_decompression_context();
void free_zstd_decompression_context(_decompression_t* context);

int is_zstd_compressed_file(const char* file_path);

size_t read_zstd_compressed(struct vh_file_t *fd, void *buf, size_t count);

size_t write_zstd_compressed(struct vh_file_t *fd, const void *buf, size_t count);

int close_zstd_compressed(struct vh_file_t *fd);

#endif //USE_Z_STD
// ---- end vh_zstd_compression.h ----

// ---- begin vh_compression_functions.h ----

#include <stdint.h>


struct vh_file_t;

extern _compression_t * (*get_compression_context_ptr)(int);
extern void(*free_compression_context_ptr)(_compression_t*);
extern _decompression_t * (*get_decompression_context_ptr)();
extern void(*free_decompression_context_ptr)(_decompression_t*);
extern int(*is_compressed_file)(const char*);
extern size_t(*read_compressed)(struct vh_file_t *, void *, size_t);
extern size_t(*write_compressed)(struct vh_file_t *, const void *, size_t);
extern int(*close_compressed)(struct vh_file_t *);


// ---- end vh_compression_functions.h ----

// ---- begin vh_compression.h ----

#include <stdint.h>

//This block should include the compression type you want to build for
#if defined(USE_Z_STD)
//Setup some other compression
#elif defined(USE_THIS_COMPRESSION_INSTEAD)
//No compression
#else
#define USE_NULL_COMPRESSION
#endif


struct vh_file_t;

//Any compression types to be added need to plug their appropriate code into these functions

//Init anything needed to keep state of your compression or configure your compression here
void vh_free_compression_context(_compression_t* context);
_compression_t * vh_get_compression_context(int compression_level);

//Init anything needed to keep state of your decompression or configure your decompression here
void vh_free_decompression_context(_decompression_t* context);
_decompression_t * vh_get_decompression_context();

//Return true if the file at file_path is a compressed file and should be decompressed
int vh_is_compressed_file(const char* file_path);

//Return number of decompressed bytes read from file
size_t vh_read_compressed(struct vh_file_t *fd, void *buf, size_t count);

//Return number of bytes written to file from the provided buffer - do not return the number of compressed bytes written
size_t vh_write_compressed(struct vh_file_t *fd, const void *buf, size_t count);

//Called when the file being read/written is to be closed - this is called first!
int vh_close_compressed(struct vh_file_t *fd);


// ---- end vh_compression.h ----

// ---- begin vh_file.h ----

#include <stdio.h>

typedef _compression_t *vh_compression;
typedef _decompression_t *vh_decompression;

typedef struct vh_file_t
{
	FILE* file;
	vh_compression compression_context;
	vh_decompression decompression_context;

} vh_file_t;

typedef vh_file_t *vh_file;

// ---- end vh_file.h ----

// ---- begin vh_internal.h ----


#include <stddef.h>
#include <stdint.h>
#include <assert.h>

struct _vh_pcapng_stream {
	struct vh_file_t *file; // vendor patch
	struct _vh_pcapng *current_block;
	int valid;
};

struct _vh_pcapng {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t *block_body;
	struct _vh_option *options;
	struct _vh_pcapng *next_block;
};

struct _vh_option {
	uint16_t custom_option_code;
	uint16_t option_length;
	// uint32_t PEN;
	uint32_t *data;
	struct _vh_option *next_option;
};

struct _vh_pcapng_mem {
	uint32_t *mem;
	uint32_t **mem_blocks;
	size_t mem_size;
	size_t block_count;
	int owner;
};

// Private Functions
struct _vh_pcapng *__copy_block(const struct _vh_pcapng *pcapng, const vh_boolean recursive);
struct _vh_option *__copy_option(const struct _vh_option *option);
size_t __get_option_total_size(const struct _vh_option *option);
uint32_t *__get_option_size(const struct _vh_option *option, size_t *size);
vh_boolean __is_section_header(const struct _vh_pcapng *section);
int __validate_section(struct _vh_pcapng *section);

// ---- end vh_internal.h ----

// ---- begin vh_platform.h ----

#ifndef UNIVERSAL
#define UNIVERSAL
#endif // UNIVERSAL

#include <stddef.h>

typedef enum {
	VH_OREAD,
	VH_OWRITE,
	VH_OAPPEND,
} __read_mode_t;

#ifdef UNIVERSAL

typedef long vh_file_pos_t;
#define INVALID_FILE NULL

#else

#error UNIMPLEMENRTED

#endif

vh_file vh_open(const char *file_name, const __read_mode_t mode);
vh_file vh_open_compression(const char *file_name, const __read_mode_t mode, int compression_level);
size_t vh_read(vh_file fd, void *buf, size_t count);
size_t vh_write(vh_file fd, const void *buf, size_t count);
size_t vh_size(vh_file fd);
int vh_close(vh_file fd);
int vh_flush(vh_file fd);
int vh_eof(vh_file fd);
vh_file_pos_t vh_get_pos(vh_file fd);
vh_file_pos_t vh_set_pos(vh_file fd, vh_file_pos_t);

// ---- end vh_platform.h ----

// ---- begin vh_pcapng.h ----



#define VH_SECTION_HEADER_BLOCK  0x0A0D0D0A
#define VH_INTERFACE_BLOCK       0x00000001
#define VH_ENHANCED_PACKET_BLOCK 0x00000006
#define VH_SIMPLE_PACKET_BLOCK   0x00000003

#define VH_CUSTOM_DATA_BLOCK     0xB16B00B5
#define VH_UNKNOWN_DATA_BLOCK    0xDEADBEEF

// "Official" option codes
#define VH_OPTION_IF_TSRESOL            0x0009
#define VH_OPTION_COMMENT               0x0001
#define VH_OPTION_SHB_HARDWARE          0x0002
#define VH_OPTION_SHB_OS                0x0003
#define VH_OPTION_SHB_USERAPPL          0x0004
#define VH_OPTION_IF_TSRESOL            0x0009

// Custom option codes
#define VH_CUSTOM_OPTION_ADDRESS_INFO   0xADD4
#define VH_CUSTOM_OPTION_FEATURE_U64    0x0064

#define BYTE_ORDER_MAGIC            0x1A2B3C4D

#define VH_KEY_REJECTED          0xFFFFFFFF

/////////////////////////////// /////////// ERROR CODES //////////////////////////////////////////////

#define VH_SUCCESS           0
#define VH_INVALID_SECTION  -1
#define VH_OUT_OF_MEMORY    -2
#define VH_INVALID_ARGUMENT -3
#define VH_NOT_FOUND        -4
#define VH_BAD_STREAM       -5
#define VH_FAILURE          -6

/////////////////////////////// STANDARD PCAPNG STRUCTURES & FUNCTIONS ///////////////////////////////
typedef struct _vh_pcapng_stream *vh_pcapng_stream;
typedef struct _vh_pcapng *vh_pcapng;
typedef struct _vh_option *vh_option;

typedef struct _vh_pair {
	uint32_t key;
	uint32_t val;
} vh_pair;

// Read/Write Functions
vh_pcapng vh_read_from_path(const char *file_name);
vh_pcapng vh_read_from_memory(const uint32_t *memory, size_t size);
//Favor vh_pcapng_to_file_stream over this function
uint32_t *vh_pcapng_to_memory(const vh_pcapng pcapng, size_t *size);

size_t vh_pcapng_to_file_stream(const vh_pcapng pcapng, vh_file file);

int vh_pcapng_to_file(const char *file_name, const vh_pcapng pcapng);
int vh_pcapng_to_compressed_file(const char *file_name, const vh_pcapng pcapng, int compression_level);

//Read next record out of file, if you give an existing record I will free it for you
//The returned record must be freed by either YOU or the next call to vh_read_record!
void vh_read_record(vh_file fd, vh_pcapng *record);

void vh_pcapng_release(vh_pcapng pcapng);

vh_pcapng_stream vh_open_stream(const char *file_name);
vh_pcapng vh_read_stream(vh_pcapng_stream pcapng);
int vh_close_stream(vh_pcapng_stream pcapng);

// For Debugging Purposes
char *vh_pcapng_to_string(vh_pcapng pcapng);
uint32_t vh_get_block_count(const vh_pcapng pcapng);
vh_pcapng vh_get_block(const vh_pcapng pcapng, uint32_t index);
size_t vh_get_size(const vh_pcapng pcapng);
void vh_pcapng_historgram(const vh_pcapng pcapng, uint32_t (*key_master)(const vh_pcapng),
		vh_pair **hist, size_t *size, size_t *rejected);
int vh_get_block_info(const vh_pcapng pcapng, vh_info info_flag, void *info_data, size_t *data_size);
vh_option vh_get_option(const vh_pcapng pcapng, uint16_t option_code);
uint16_t vh_get_option_code(const vh_option option);
const vh_option vh_get_next_option(const vh_option option);
uint32_t *vh_get_option_data(const vh_option option);
uint16_t vh_get_option_length(const vh_option option);

// Manipulation Functions
vh_option vh_create_option(const uint16_t option_code, const uint16_t option_length, void *option_value);
int vh_add_option(vh_pcapng section, vh_pcapng pcapng, vh_option option, vh_boolean copy);
int vh_update_option(vh_pcapng section, vh_pcapng pcapng, vh_option option);
int vh_add_block(vh_pcapng block, vh_pcapng next_block);
int vh_subcapture(const vh_pcapng section, vh_boolean (*predicate)(const vh_pcapng), vh_pcapng *subcapture);
int vh_iterate(const vh_pcapng pcapng, vh_boolean (*stop_fn)(const vh_pcapng, void *), void *args);
int vh_ip_flow(vh_pcapng *sectionp, vh_pcapng **flows, size_t *flow_count, size_t *dropped);

// Allocation and free functions
vh_option vh_alloc_option(uint16_t option_length);
vh_pcapng vh_alloc_block(uint32_t block_type, const uint32_t *block_body, uint32_t block_body_length);
void vh_free_option(vh_option option);
void vh_free_block(vh_pcapng pcapng);

// Advanced Interaction
typedef enum {
	VH_FEATURE_BITMASK = 0,
	VH_FEATURE_BYTE = 1,
	VH_FEATURE_SHORT = 2,
	VH_FEATURE_FLOAT = 4,
	VH_FEATURE_DOUBLE = 5,
} vh_feature_t;
int vh_section_feature_extraction(const vh_pcapng section, int (*extractor)(const vh_pcapng, void *, size_t),
		void **feature_vector, const size_t feature_vector_size, const vh_feature_t type);

/////////////////////////////// CONTINUOUS MEMORY BLOCK STRUCTURES & FUNCTIONS ///////////////////////////////

typedef struct _vh_pcapng_mem *vh_pcapng_mem;

// Continuous Memory Functions
struct _vh_pcapng_mem *vh_no_copy_from_memory(uint32_t *memory, size_t size, int is_owner);
void vh_pcapng_mem_release(struct _vh_pcapng_mem *pcapng);


// ---- end vh_pcapng.h ----

// ---- begin vh_pcapng_ext.h ----



#include <stddef.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <Winsock2.h>
#include <time.h>
#else
#include <sys/time.h>
#endif

#ifndef NULL
#define NULL   ((void *) 0)
#endif

#define MAX_SUPPORTED_INTERFACE_BLOCKS 32

struct _vh_pcapng_t;
typedef struct _vh_pcapng_t vh_pcapng_t;

typedef struct _vh_packet_header {
	uint32_t interface_id;
	struct timespec timestamp;
	uint32_t captured_length;
	uint32_t original_length;
	uint16_t data_link;
	char* comment;
	uint16_t comment_length;
} vh_packet_header;

typedef struct _vh_pcapng_file_info {
	uint16_t major_version;
	uint16_t minor_version;
	char *file_comment;
	size_t file_comment_size;
	char *hardware_desc;
	size_t hardware_desc_size;
	char *os_desc;
	size_t os_desc_size;
	char *user_app_desc;
	size_t user_app_desc_size;
	size_t interface_block_count;
	uint16_t link_types[MAX_SUPPORTED_INTERFACE_BLOCKS];
	uint64_t timestamp_ticks_per_second[MAX_SUPPORTED_INTERFACE_BLOCKS]; // vendor patch

} vh_pcapng_file_info;


vh_pcapng_t *vh_pcapng_open_read(const char* file_path, vh_boolean read_all_interfaces);

//Set compression level to 0 to disable compression!
vh_pcapng_t *vh_pcapng_open_write(const char* file_path, vh_pcapng_file_info *file_info, int compression_level);

vh_pcapng_t *vh_pcapng_open_append(const char* file_path);

vh_pcapng_file_info *vh_create_default_file_info();

vh_pcapng_file_info *vh_create_file_info(const char *os_desc, const char *hardware_desc, const char *user_app_desc, const char *file_comment);

void vh_free_file_info(vh_pcapng_file_info *info);

vh_pcapng_file_info *vh_pcang_get_file_info(vh_pcapng_t *pcapng);

int vh_get_next_packet(vh_pcapng_t *pcapng, vh_packet_header *packet_header, const uint8_t **packet_data);

void vh_write_packet(vh_pcapng_t *pcapng, const vh_packet_header *packet_header, const uint8_t *packet_data);

void vh_pcapng_close(vh_pcapng_t *pcapng);

void vh_pcapng_flush(vh_pcapng_t *pcapng);


// ---- end vh_pcapng_ext.h ----

// ---- begin vh_util.h ----

#define PADD32(val, aligned_val_p) do { \
		*aligned_val_p = (val % sizeof(uint32_t)) == 0 ? val : (val / sizeof(uint32_t) + 1) * sizeof(uint32_t); \
} while (0)


// ---- end vh_util.h ----

