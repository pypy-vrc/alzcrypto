#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#pragma hdrstop

static uint32_t crc32_table[256] = {
	0x00000000UL, 0x77073096UL, 0xee0e612cUL, 0x990951baUL, 0x076dc419UL,
	0x706af48fUL, 0xe963a535UL, 0x9e6495a3UL, 0x0edb8832UL, 0x79dcb8a4UL,
	0xe0d5e91eUL, 0x97d2d988UL, 0x09b64c2bUL, 0x7eb17cbdUL, 0xe7b82d07UL,
	0x90bf1d91UL, 0x1db71064UL, 0x6ab020f2UL, 0xf3b97148UL, 0x84be41deUL,
	0x1adad47dUL, 0x6ddde4ebUL, 0xf4d4b551UL, 0x83d385c7UL, 0x136c9856UL,
	0x646ba8c0UL, 0xfd62f97aUL, 0x8a65c9ecUL, 0x14015c4fUL, 0x63066cd9UL,
	0xfa0f3d63UL, 0x8d080df5UL, 0x3b6e20c8UL, 0x4c69105eUL, 0xd56041e4UL,
	0xa2677172UL, 0x3c03e4d1UL, 0x4b04d447UL, 0xd20d85fdUL, 0xa50ab56bUL,
	0x35b5a8faUL, 0x42b2986cUL, 0xdbbbc9d6UL, 0xacbcf940UL, 0x32d86ce3UL,
	0x45df5c75UL, 0xdcd60dcfUL, 0xabd13d59UL, 0x26d930acUL, 0x51de003aUL,
	0xc8d75180UL, 0xbfd06116UL, 0x21b4f4b5UL, 0x56b3c423UL, 0xcfba9599UL,
	0xb8bda50fUL, 0x2802b89eUL, 0x5f058808UL, 0xc60cd9b2UL, 0xb10be924UL,
	0x2f6f7c87UL, 0x58684c11UL, 0xc1611dabUL, 0xb6662d3dUL, 0x76dc4190UL,
	0x01db7106UL, 0x98d220bcUL, 0xefd5102aUL, 0x71b18589UL, 0x06b6b51fUL,
	0x9fbfe4a5UL, 0xe8b8d433UL, 0x7807c9a2UL, 0x0f00f934UL, 0x9609a88eUL,
	0xe10e9818UL, 0x7f6a0dbbUL, 0x086d3d2dUL, 0x91646c97UL, 0xe6635c01UL,
	0x6b6b51f4UL, 0x1c6c6162UL, 0x856530d8UL, 0xf262004eUL, 0x6c0695edUL,
	0x1b01a57bUL, 0x8208f4c1UL, 0xf50fc457UL, 0x65b0d9c6UL, 0x12b7e950UL,
	0x8bbeb8eaUL, 0xfcb9887cUL, 0x62dd1ddfUL, 0x15da2d49UL, 0x8cd37cf3UL,
	0xfbd44c65UL, 0x4db26158UL, 0x3ab551ceUL, 0xa3bc0074UL, 0xd4bb30e2UL,
	0x4adfa541UL, 0x3dd895d7UL, 0xa4d1c46dUL, 0xd3d6f4fbUL, 0x4369e96aUL,
	0x346ed9fcUL, 0xad678846UL, 0xda60b8d0UL, 0x44042d73UL, 0x33031de5UL,
	0xaa0a4c5fUL, 0xdd0d7cc9UL, 0x5005713cUL, 0x270241aaUL, 0xbe0b1010UL,
	0xc90c2086UL, 0x5768b525UL, 0x206f85b3UL, 0xb966d409UL, 0xce61e49fUL,
	0x5edef90eUL, 0x29d9c998UL, 0xb0d09822UL, 0xc7d7a8b4UL, 0x59b33d17UL,
	0x2eb40d81UL, 0xb7bd5c3bUL, 0xc0ba6cadUL, 0xedb88320UL, 0x9abfb3b6UL,
	0x03b6e20cUL, 0x74b1d29aUL, 0xead54739UL, 0x9dd277afUL, 0x04db2615UL,
	0x73dc1683UL, 0xe3630b12UL, 0x94643b84UL, 0x0d6d6a3eUL, 0x7a6a5aa8UL,
	0xe40ecf0bUL, 0x9309ff9dUL, 0x0a00ae27UL, 0x7d079eb1UL, 0xf00f9344UL,
	0x8708a3d2UL, 0x1e01f268UL, 0x6906c2feUL, 0xf762575dUL, 0x806567cbUL,
	0x196c3671UL, 0x6e6b06e7UL, 0xfed41b76UL, 0x89d32be0UL, 0x10da7a5aUL,
	0x67dd4accUL, 0xf9b9df6fUL, 0x8ebeeff9UL, 0x17b7be43UL, 0x60b08ed5UL,
	0xd6d6a3e8UL, 0xa1d1937eUL, 0x38d8c2c4UL, 0x4fdff252UL, 0xd1bb67f1UL,
	0xa6bc5767UL, 0x3fb506ddUL, 0x48b2364bUL, 0xd80d2bdaUL, 0xaf0a1b4cUL,
	0x36034af6UL, 0x41047a60UL, 0xdf60efc3UL, 0xa867df55UL, 0x316e8eefUL,
	0x4669be79UL, 0xcb61b38cUL, 0xbc66831aUL, 0x256fd2a0UL, 0x5268e236UL,
	0xcc0c7795UL, 0xbb0b4703UL, 0x220216b9UL, 0x5505262fUL, 0xc5ba3bbeUL,
	0xb2bd0b28UL, 0x2bb45a92UL, 0x5cb36a04UL, 0xc2d7ffa7UL, 0xb5d0cf31UL,
	0x2cd99e8bUL, 0x5bdeae1dUL, 0x9b64c2b0UL, 0xec63f226UL, 0x756aa39cUL,
	0x026d930aUL, 0x9c0906a9UL, 0xeb0e363fUL, 0x72076785UL, 0x05005713UL,
	0x95bf4a82UL, 0xe2b87a14UL, 0x7bb12baeUL, 0x0cb61b38UL, 0x92d28e9bUL,
	0xe5d5be0dUL, 0x7cdcefb7UL, 0x0bdbdf21UL, 0x86d3d2d4UL, 0xf1d4e242UL,
	0x68ddb3f8UL, 0x1fda836eUL, 0x81be16cdUL, 0xf6b9265bUL, 0x6fb077e1UL,
	0x18b74777UL, 0x88085ae6UL, 0xff0f6a70UL, 0x66063bcaUL, 0x11010b5cUL,
	0x8f659effUL, 0xf862ae69UL, 0x616bffd3UL, 0x166ccf45UL, 0xa00ae278UL,
	0xd70dd2eeUL, 0x4e048354UL, 0x3903b3c2UL, 0xa7672661UL, 0xd06016f7UL,
	0x4969474dUL, 0x3e6e77dbUL, 0xaed16a4aUL, 0xd9d65adcUL, 0x40df0b66UL,
	0x37d83bf0UL, 0xa9bcae53UL, 0xdebb9ec5UL, 0x47b2cf7fUL, 0x30b5ffe9UL,
	0xbdbdf21cUL, 0xcabac28aUL, 0x53b39330UL, 0x24b4a3a6UL, 0xbad03605UL,
	0xcdd70693UL, 0x54de5729UL, 0x23d967bfUL, 0xb3667a2eUL, 0xc4614ab8UL,
	0x5d681b02UL, 0x2a6f2b94UL, 0xb40bbe37UL, 0xc30c8ea1UL, 0x5a05df1bUL,
	0x2d02ef8dUL
};

uint32_t key0, key1, key2;
uint16_t enc_bit_flag;
uint16_t enc_last_mod_time;
uint32_t enc_crc_32;
uint8_t enc[12];

void dump(const void* buf, size_t len)
{
	static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	unsigned char* begin, * end, c;
	char line[64 + 1];
	size_t i;

	begin = (unsigned char*)buf;
	end = begin + len;

	while (begin < end) {
		line[64] = 0;
		memset(line, ' ', 64);
		i = (size_t)(end - begin);
		if (i > 16)
			i = 16;
		do {
			c = begin[--i];
			line[i * 3] = hex[c >> 4];
			line[i * 3 + 1] = hex[c & 15];
			line[i + 48] = (c > 31 && c < 127) ? c : '.';
		} while (i);
		begin += 16;
		printf("%.*s\n", 64, line);
	}
}

__forceinline uint8_t decrypt_byte(void)
{
	uint16_t v = (key2 & 65535) | 2;
	return ((v * (v ^ 1)) >> 8) & 255;
}

__forceinline void update_keys(uint8_t c)
{
	// key0 = CRC32(key0, c);
	key0 = crc32_table[(key0 ^ c) & 255] ^ (key0 >> 8);
	key1 = key1 + (key0 & 255);
	key1 = key1 * 134775813 + 1;
	// key2 = CRC32(key2, key1 >> 24);
	key2 = crc32_table[(key2 ^ (key1 >> 24)) & 255] ^ (key2 >> 8);
}

void challenge(const char* password)
{
	printf("----\n");

	key0 = 305419896;
	key1 = 591751049;
	key2 = 878082192;

	for (const uint8_t* p = password; *p; ++p) {
		update_keys(*p);
	}

	printf("key0=%08X key1=%08X key2=%08X\n", key0, key1, key2);

	uint8_t buf[12];
	update_keys(buf[0] = enc[0] ^ decrypt_byte());
	update_keys(buf[1] = enc[1] ^ decrypt_byte());
	update_keys(buf[2] = enc[2] ^ decrypt_byte());
	update_keys(buf[3] = enc[3] ^ decrypt_byte());
	update_keys(buf[4] = enc[4] ^ decrypt_byte());
	update_keys(buf[5] = enc[5] ^ decrypt_byte());
	update_keys(buf[6] = enc[6] ^ decrypt_byte());
	update_keys(buf[7] = enc[7] ^ decrypt_byte());
	update_keys(buf[8] = enc[8] ^ decrypt_byte());
	update_keys(buf[9] = enc[9] ^ decrypt_byte());
	update_keys(buf[10] = enc[10] ^ decrypt_byte());
	update_keys(buf[11] = enc[11] ^ decrypt_byte());

	printf("buf:\n");
	dump(buf, 12);

	printf("%04X header\n", *(uint16_t*)&buf[10]);
	printf("%04X crc32\n", enc_crc_32 >> 16);
	printf("%04X time\n", enc_last_mod_time);

	if (*(uint16_t*)&buf[10] == (enc_bit_flag & 8 ? enc_last_mod_time : (enc_crc_32 >> 16))) {
		printf("PASSWORD MATCH\n");
	}
	else {
		printf("PASSWORD DID NOT MATCH\n");
	}
}

#pragma pack(push, 1)

typedef struct _ALZ_LOCAL_HEADER {
	uint32_t header;
	uint16_t filename_length;
	uint8_t file_attribute; // ?
	uint16_t last_mod_time;
	uint16_t last_mod_date;
	uint16_t bit_flag;
} ALZ_LOCAL_HEADER;

#pragma pack(pop)

void parse_alz(uint8_t* begin, uint8_t* end)
{
	uint8_t* ptr = NULL;

	for (uint8_t* p = begin; p + 12 < end; ++p) {
		if (memcmp(p, "\x41\x4C\x5A\x01\x0A\x00\x00\x00\x42\x4C\x5A\x01", 12) == 0) {
			ptr = p + 8;
			break;
		}
	}

	if (ptr == NULL) {
		return;
	}

	while (ptr + 13 < end) {
		ALZ_LOCAL_HEADER* lh = (ALZ_LOCAL_HEADER*)ptr;

		if (lh->header != 0x015A4C42) {
			break;
		}

		printf("[ALZ_LOCAL_HEADER]\n");
		printf("%08X header\n", lh->header);
		printf("%08X filename_length\n", lh->filename_length);
		printf("%08X file_attribute\n", lh->file_attribute);
		printf("%08X last_mod_time\n", lh->last_mod_time);
		printf("%08X last_mod_date\n", lh->last_mod_date);
		printf("%08X bit_flag\n", lh->bit_flag);

		ptr += sizeof(*lh);

		uint16_t comp_method = 0;
		uint32_t crc_32 = 0;
		uint32_t comp_size = 0;
		uint32_t uncomp_size = 0;

		uint8_t byte_length = (lh->bit_flag >> 4) & 15;
		printf("%08X byte_length\n", byte_length);

		if (byte_length) {
			if (byte_length != 1 &&
				byte_length != 2 &&
				byte_length != 4) {
				break;
			}

			comp_method = *(uint16_t*)ptr;
			ptr += 2;
			crc_32 = *(uint32_t*)ptr;
			ptr += 4;
			memcpy(&comp_size, ptr, byte_length);
			ptr += byte_length;
			memcpy(&uncomp_size, ptr, byte_length);
			ptr += byte_length;
		}

		printf("%08X comp_method\n", comp_method);
		printf("%08X crc_32\n", crc_32);
		printf("%08X comp_size\n", comp_size);
		printf("%08X uncomp_size\n", uncomp_size);

		printf("filename:\n");
		dump(ptr, lh->filename_length);
		ptr += lh->filename_length;

		if (lh->bit_flag & 1) {
			printf("encryption header:\n");
			dump(ptr, 12);

			// copy parameters
			enc_bit_flag = lh->bit_flag;
			enc_last_mod_time = lh->last_mod_time;
			enc_crc_32 = crc_32;
			memcpy(enc, ptr, 12);
		}

		ptr += comp_size;
	}
}

void test_alz(void)
{
	HANDLE file = CreateFileW(L"test.alz", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return;
	}

	HANDLE map = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map == NULL) {
		CloseHandle(file);
		return;
	}

	void* p = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if (p != NULL) {
		parse_alz((uint8_t*)p, (uint8_t*)p + GetFileSize(file, NULL));
	}

	CloseHandle(map);
	CloseHandle(file);
}

#pragma pack(push, 1)

typedef struct _ZIP_LOCAL_HEADER {
	uint32_t header;                 // ZIP local header, always equals 0x04034b50
	uint16_t version;                // Minimum version for extracting
	uint16_t bit_flag;               // Bit flag
	uint16_t comp_method;            // Compression method (0 - uncompressed, 8 - deflate)
	uint16_t last_mod_time;          // File modification time
	uint16_t last_mod_date;          // File modification date
	uint32_t crc_32;                 // CRC-32 hash
	uint32_t comp_size;              // Compressed size
	uint32_t uncomp_size;            // Uncompressed size
	uint16_t filename_length;        // Length of the file name
	uint16_t extrafield_length;      // Length field with additional data
} ZIP_LOCAL_HEADER;

typedef struct _ZIP_CENTRAL_DIRECTORY {
	uint32_t header;                 // Central directory header, always equals 0x02014B50
	uint16_t made_ver;               // Version made by
	uint16_t version;                // Minimum version for extracting
	uint16_t bit_flag;               // Bit flag
	uint16_t comp_method;            // Compressed method (0 - uncompressed, 8 - deflate)
	uint16_t last_mod_time;          // File modification time
	uint16_t last_mod_date;          // File modification date
	uint32_t crc_32;                 // CRC32 hash
	uint32_t comp_size;              // Compressed size
	uint32_t uncomp_size;            // Uncompressed size
	uint16_t filename_length;        // Length of the file name
	uint16_t extrafield_length;      // Length field with additional data
	uint16_t file_comment_length;    // Length of comment file
	uint16_t disk_number_start;      // Disk number start
	uint16_t internal_file_attr;     // Internal file attributes
	uint32_t external_file_attr;     // External file attributes
	uint32_t offset_header;          // Relative offset of local header
} ZIP_CENTRAL_DIRECTORY;

typedef struct _ZIP_END_RECORD {
	uint32_t header;                // Header of end central directory record, always equals 0x06054b50
	uint16_t disk_number;           // Number of this disk
	uint16_t disk_number_cd;        // Number of the disk with the start of the central directory
	uint16_t total_entries_disk;    // Total number of entries in the central directory on this disk
	uint16_t total_entries;         // Total number of entries in the central directory
	uint32_t size_central_dir;      // Size of central directory
	uint32_t start_cd_offset;       // Starting disk number
	uint16_t file_comment_length;   // File comment length
} ZIP_END_RECORD;

#pragma pack(pop)

void parse_zip(uint8_t* begin, uint8_t* end)
{
	ZIP_END_RECORD* end_record = NULL;

	for (uint8_t* p = end - 4; p >= begin; --p) {
		if (((ZIP_END_RECORD*)p)->header == 0x06054B50) {
			// TODO: more validate
			end_record = (ZIP_END_RECORD*)p;
			break;
		}
	}

	if (end_record == NULL) {
		return;
	}

	printf("----\n");
	printf("[ZIP_END_RECORD]\n");
	printf("%08X header \n", end_record->header);
	printf("%08X disk_number\n", end_record->disk_number);
	printf("%08X disk_number_cd\n", end_record->disk_number_cd);
	printf("%08X total_entries_disk\n", end_record->total_entries_disk);
	printf("%08X total_entries\n", end_record->total_entries);
	printf("%08X size_central_dir\n", end_record->size_central_dir);
	printf("%08X start_cd_offset\n", end_record->start_cd_offset);
	printf("%08X file_comment_length\n", end_record->file_comment_length);

	uint8_t* p = begin + end_record->start_cd_offset;

	for (;;) {
		ZIP_CENTRAL_DIRECTORY* cd = (ZIP_CENTRAL_DIRECTORY*)p;

		if (cd->header != 0x02014B50) {
			break;
		}

		ZIP_LOCAL_HEADER* lh = (ZIP_LOCAL_HEADER*)(begin + cd->offset_header);

		if (lh->header != 0x04034B50) {
			break;
		}

		printf("----\n");
		printf("[ZIP_CENTRAL_DIRECTORY]\n");
		printf("%08X header\n", cd->header);
		printf("%08X made_ver\n", cd->made_ver);
		printf("%08X version\n", cd->version);
		printf("%08X bit_flag\n", cd->bit_flag);
		printf("%08X comp_method\n", cd->comp_method);
		printf("%08X last_mod_time\n", cd->last_mod_time);
		printf("%08X last_mod_date\n", cd->last_mod_date);
		printf("%08X crc_32\n", cd->crc_32);
		printf("%08X comp_size\n", cd->comp_size);
		printf("%08X uncomp_size\n", cd->uncomp_size);
		printf("%08X filename_length\n", cd->filename_length);
		printf("%08X extrafield_length\n", cd->extrafield_length);
		printf("%08X file_comment_length\n", cd->file_comment_length);
		printf("%08X disk_number_start\n", cd->disk_number_start);
		printf("%08X internal_file_attr\n", cd->internal_file_attr);
		printf("%08X external_file_attr\n", cd->external_file_attr);
		printf("%08X offset_header\n", cd->offset_header);

		p += sizeof(*cd);

		printf("filename:\n");
		dump(p, cd->filename_length);
		p += cd->filename_length;

		if (cd->extrafield_length) {
			printf("extrafield:\n");
			dump(p, cd->extrafield_length);
			p += cd->extrafield_length;
		}

		if (cd->file_comment_length) {
			printf("file_comment:\n");
			dump(p, cd->file_comment_length);
			p += cd->file_comment_length;
		}

		printf("----\n");
		printf("[ZIP_LOCAL_HEADER]\n");
		printf("%08X header\n", lh->header);
		printf("%08X version\n", lh->version);
		printf("%08X bit_flag\n", lh->bit_flag);
		printf("%08X comp_method\n", lh->comp_method);
		printf("%08X last_mod_time\n", lh->last_mod_time);
		printf("%08X last_mod_date\n", lh->last_mod_date);
		printf("%08X crc_32\n", lh->crc_32);
		printf("%08X comp_size\n", lh->comp_size);
		printf("%08X uncomp_size\n", lh->uncomp_size);
		printf("%08X filename_length\n", lh->filename_length);
		printf("%08X extrafield_length\n", lh->extrafield_length);

		uint8_t* pp = (uint8_t*)lh;
		pp += sizeof(*lh);

		printf("filename:\n");
		dump(pp, lh->filename_length);
		pp += lh->filename_length;

		if (lh->extrafield_length) {
			printf("extrafield:\n");
			dump(pp, lh->extrafield_length);
			pp += lh->extrafield_length;
		}

		if (lh->bit_flag & 1) {
			printf("encryption header:\n");
			dump(pp, 12);

			// copy parameters
			enc_bit_flag = lh->bit_flag;
			enc_last_mod_time = lh->last_mod_time;
			enc_crc_32 = lh->crc_32;
			memcpy(enc, pp, 12);
		}

		// pp += lh->comp_size;

		if (GetTickCount64()) {
			break;
		}
	}
}

void test_zip(void)
{
	HANDLE file = CreateFileW(L"test.zip", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return;
	}

	HANDLE map = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map == NULL) {
		CloseHandle(file);
		return;
	}

	void* p = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if (p != NULL) {
		parse_zip((uint8_t*)p, (uint8_t*)p + GetFileSize(file, NULL));
	}

	CloseHandle(map);
	CloseHandle(file);
}

int main(int argc, const char** argv)
{
	// test_zip();
	test_alz();
	challenge("");
	return 0;
}
