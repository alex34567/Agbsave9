#include "fs.h"
#include "draw.h"
#include "hid.h"
#include "platform.h"
#include "decryptor/aes.h"
#include "decryptor/sha.h"
#include "decryptor/decryptor.h"
#include "decryptor/nand.h"
#include "fatfs/sdmmc.h"

// return values for NAND header check
#define NAND_HDR_UNK  0 // should be zero
#define NAND_HDR_O3DS 1 
#define NAND_HDR_N3DS 2

// these offsets are used by Multi EmuNAND Creator / CakesFW
#define EMUNAND_MULTI_SECTORS ((getMMCDevice(0)->total_size > 0x200000) ?  0x400000 : 0x200000)

// minimum sizes for O3DS / N3DS NAND
// see: http://3dbrew.org/wiki/Flash_Filesystem
#define NAND_MIN_SIZE ((GetUnitPlatform() == PLATFORM_3DS) ? 0x3AF00000 : 0x4D800000)

// see below
#define IS_NAND_HEADER(hdr) ((memcmp(buffer + 0x100, nand_magic_n3ds, 0x60) == 0) ||\
                             (memcmp(buffer + 0x100, nand_magic_o3ds, 0x60) == 0))

// from an actual N3DS NCSD NAND header, same for all
static u8 nand_magic_n3ds[0x60] = {
    0x4E, 0x43, 0x53, 0x44, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x04, 0x03, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00, 0x00, 0x88, 0x05, 0x00, 0x80, 0x01, 0x00, 0x00,
    0x80, 0x89, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80, 0xA9, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00,
    0x80, 0xC9, 0x05, 0x00, 0x80, 0xF6, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// from an actual O3DS NCSD NAND header, same for all
static u8 nand_magic_o3ds[0x60] = {
    0x4E, 0x43, 0x53, 0x44, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x04, 0x03, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00, 0x00, 0x88, 0x05, 0x00, 0x80, 0x01, 0x00, 0x00,
    0x80, 0x89, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80, 0xA9, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00,
    0x80, 0xC9, 0x05, 0x00, 0x80, 0xAE, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// see: http://3dbrew.org/wiki/Flash_Filesystem
static PartitionInfo partitions[] = {
    { "TWLN",    {0xE9, 0x00, 0x00, 0x54, 0x57, 0x4C, 0x20, 0x20}, 0x00012E00, 0x08FB5200, 0x3, AES_CNT_TWLNAND_MODE },
    { "TWLP",    {0xE9, 0x00, 0x00, 0x54, 0x57, 0x4C, 0x20, 0x20}, 0x09011A00, 0x020B6600, 0x3, AES_CNT_TWLNAND_MODE },
    { "AGBSAVE", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0x0B100000, 0x00030000, 0x7, AES_CNT_CTRNAND_MODE },
    { "FIRM",    {0x46, 0x49, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00}, 0x0B130000, 0x00400000, 0x6, AES_CNT_CTRNAND_MODE },
    { "FIRM",    {0x46, 0x49, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00}, 0x0B530000, 0x00400000, 0x6, AES_CNT_CTRNAND_MODE },
    { "CTRNAND", {0xE9, 0x00, 0x00, 0x43, 0x54, 0x52, 0x20, 0x20}, 0x0B95CA00, 0x2F3E3600, 0x4, AES_CNT_CTRNAND_MODE }, // O3DS
    { "CTRNAND", {0xE9, 0x00, 0x00, 0x43, 0x54, 0x52, 0x20, 0x20}, 0x0B95AE00, 0x41D2D200, 0x5, AES_CNT_CTRNAND_MODE }, // N3DS
    { "CTRNAND", {0xE9, 0x00, 0x00, 0x43, 0x54, 0x52, 0x20, 0x20}, 0x0B95AE00, 0x41D2D200, 0x4, AES_CNT_CTRNAND_MODE }  // NO3DS
};

static u32 emunand_header = 0;
static u32 emunand_offset = 0;


u32 CheckEmuNand(void)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 nand_size_sectors = getMMCDevice(0)->total_size;
    u32 nand_size_sectors_min = NAND_MIN_SIZE / NAND_SECTOR_SIZE;
    u32 multi_sectors = EMUNAND_MULTI_SECTORS;
    u32 ret = EMUNAND_NOT_READY;

    // check the MBR for presence of a hidden partition
    u32 hidden_sectors = NumHiddenSectors();
    
    for (u32 offset_sector = 0; offset_sector + nand_size_sectors_min <= hidden_sectors; offset_sector += multi_sectors) {
        // check for RedNAND type EmuNAND
        sdmmc_sdcard_readsectors(offset_sector + 1, 1, buffer);
        if (IS_NAND_HEADER(buffer)) {
            ret |= EMUNAND_REDNAND << (2 * (offset_sector / multi_sectors)); 
            continue;
        }
        // check for Gateway type EmuNAND
        sdmmc_sdcard_readsectors(offset_sector + nand_size_sectors, 1, buffer);
        if ((hidden_sectors > offset_sector + nand_size_sectors) && IS_NAND_HEADER(buffer)) {
            ret |= EMUNAND_GATEWAY << (2 * (offset_sector / multi_sectors)); 
            continue;
        }
        // EmuNAND ready but not set up
        ret |= EMUNAND_READY << (2 * (offset_sector / multi_sectors));
    }
    
    return ret;
}

u32 SetNand(bool set_emunand, bool force_emunand)
{
    if (set_emunand) {
        u32 emunand_state = CheckEmuNand();
        u32 emunand_count = 0;
        u32 offset_sector = 0;
        
        for (emunand_count = 0; (emunand_state >> (2 * emunand_count)) & 0x3; emunand_count++);
        if (emunand_count > 1) { // multiple EmuNANDs -> use selector
            u32 emunand_no = 0;
            Debug("Use arrow keys and <A> to choose EmuNAND");
            while (true) {
                u32 emunandn_state = (emunand_state >> (2 * emunand_no)) & 0x3;
                offset_sector = emunand_no * EMUNAND_MULTI_SECTORS;
                Debug("\rEmuNAND #%u: %s", emunand_no, (emunandn_state == EMUNAND_READY) ? "EmuNAND ready" : (emunandn_state == EMUNAND_GATEWAY) ? "GW EmuNAND" : "RedNAND");
                // user input routine
                u32 pad_state = InputWait();
                if (pad_state & BUTTON_DOWN) {
                    emunand_no = (emunand_no + 1) % emunand_count;
                } else if (pad_state & BUTTON_UP) {
                    emunand_no = (emunand_no) ?  emunand_no - 1 : emunand_count - 1;
                } else if (pad_state & BUTTON_A) {
                    Debug("EmuNAND #%u", emunand_no);
                    emunand_state = emunandn_state;
                    break;
                } else if (pad_state & BUTTON_B) {
                    Debug("(cancelled by user)");
                    return 2;
                }
            }
        }
        
        if ((emunand_state == EMUNAND_READY) && force_emunand)
            emunand_state = EMUNAND_REDNAND;
        switch (emunand_state) {
            case EMUNAND_NOT_READY:
                Debug("SD is not formatted for EmuNAND");
                return 1;
            case EMUNAND_GATEWAY:
                emunand_header = offset_sector + getMMCDevice(0)->total_size;
                emunand_offset = offset_sector;
                Debug("Using EmuNAND @ %06X/%06X", emunand_header, emunand_offset);
                return 0;
            case EMUNAND_REDNAND:
                emunand_header = offset_sector + 1;
                emunand_offset = offset_sector + 1;
                Debug("Using RedNAND @ %06X/%06X", emunand_header, emunand_offset);
                return 0;
            default:
                Debug("EmuNAND is not available");
                return 1;
        }
    } else {
        emunand_header = 0;
        emunand_offset = 0;
        return 0;
    }
}

static inline int ReadNandSectors(u32 sector_no, u32 numsectors, u8 *out)
{
    if (emunand_header) {
        if (sector_no == 0) {
            int errorcode = sdmmc_sdcard_readsectors(emunand_header, 1, out);
            if (errorcode) return errorcode;
            sector_no = 1;
            numsectors--;
            out += 0x200;
        }
        return (numsectors) ? sdmmc_sdcard_readsectors(sector_no + emunand_offset, numsectors, out) : 0;
    } else return sdmmc_nand_readsectors(sector_no, numsectors, out);
}

static inline int WriteNandSectors(u32 sector_no, u32 numsectors, u8 *in)
{
    if (emunand_header) {
        if (sector_no == 0) {
            int errorcode = sdmmc_sdcard_writesectors(emunand_header, 1, in);
            if (errorcode) return errorcode;
            sector_no = 1;
            numsectors--;
            in += 0x200;
        }
        return (numsectors) ? sdmmc_sdcard_writesectors(sector_no + emunand_offset, numsectors, in) : 0;
    } else return sdmmc_nand_writesectors(sector_no, numsectors, in);
}

static u32 CheckNandHeader(u8* header) {
    u8 lheader[0x200];
    
    if (header != NULL)
        memcpy(lheader, header, 0x200);
    else if (ReadNandSectors(0, 1, lheader) != 0)
        return NAND_HDR_UNK;
    
    if (memcmp(lheader + 0x100, nand_magic_n3ds, 0x60) == 0) {
        return NAND_HDR_N3DS;
    } else if (memcmp(lheader + 0x100, nand_magic_o3ds, 0x60) == 0) {
        return NAND_HDR_O3DS;
    } 
    
    return NAND_HDR_UNK;
}

static u32 CheckNandDumpIntegrity(const char* path) {
    u8 header[0x200];
    u32 nand_hdr_type = NAND_HDR_UNK;
    
    if (!DebugFileOpen(path))
        return 1;
    
    // size check
    if (FileGetSize() < NAND_MIN_SIZE) {
        FileClose();
        Debug("NAND dump is too small");
        return 1;
    }
    
    // header check
    if(!DebugFileRead(header, 0x200, 0)) {
        FileClose();
        return 1;
    }
    nand_hdr_type = CheckNandHeader(header);
    if ((nand_hdr_type == NAND_HDR_UNK) || (GetUnitPlatform() == PLATFORM_3DS && (nand_hdr_type != NAND_HDR_O3DS))) {
        FileClose();
        Debug("NAND header not recognized");
        return 1;
    }
    
    // magic number / crypto check
    for (u32 p_num = 0; p_num < 6; p_num++) { 
        PartitionInfo* partition = partitions + p_num; // workaround for files, not possible with GetPartitionInfo()
        if ((p_num == 5) && (GetUnitPlatform() == PLATFORM_N3DS)) // special N3DS partition types
            partition = (nand_hdr_type == NAND_HDR_N3DS) ? partitions + 6 : partitions + 7;
        CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = 16, .buffer = header, .mode = partition->mode};
        if (GetNandCtr(info.ctr, partition->offset) != 0) {
            FileClose();
            return 1;
        }
        if (!DebugFileRead(header, 16, partition->offset)) {
            FileClose();
            return 1;
        }
        CryptBuffer(&info);
        if ((partition->magic[0] != 0xFF) && (memcmp(partition->magic, header, 8) != 0)) {
            FileClose();
            Debug("Not a proper NAND backup for this 3DS");
            if (partition->keyslot == 0x05)
                Debug("(or slot0x05keyY not set up)");
            return 1;
        }
    }
    
    // firm hash check
    u32 firm_corruption = 0;
    for (u32 f_num = 0; f_num < 2; f_num++) { 
        PartitionInfo* partition = partitions + 3 + f_num;
        CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = 0x200, .buffer = header, .mode = partition->mode};
        if ((GetNandCtr(info.ctr, partition->offset) != 0) || (!DebugFileRead(header, 0x200, partition->offset))) {
            FileClose();
            return 1;
        }
        CryptBuffer(&info);
        for (u32 section = 0; section < 4; section++) {
            u8 l_sha256[32];
            u32 offset = partition->offset + getle32(header + 0x40 + 0x00 + (0x30*section));
            u32 size = getle32(header + 0x40 + 0x08 + (0x30*section));
            u8* sha256 = header + 0x40 + 0x10 + (0x30*section);
            if (!size)
                continue;
            sha_init(SHA256_MODE);
            for (u32 i = 0; i < size; i += BUFFER_MAX_SIZE) {
                u8* buffer = BUFFER_ADDRESS;
                u32 read_bytes = min(BUFFER_MAX_SIZE, (size - i));
                info.size = read_bytes;
                info.buffer = buffer;
                GetNandCtr(info.ctr, offset + i);
                FileRead(buffer, read_bytes, offset + i);
                CryptBuffer(&info);
                sha_update(buffer, read_bytes);
            }
            sha_get(l_sha256);
            if (memcmp(l_sha256, sha256, 32) != 0) {
                Debug("FIRM%u section%u hash mismatch", f_num, section);
                firm_corruption |= (1<<f_num);
            }
        }
    }
    if ((firm_corruption == 0x1) && ((*(vu32*) 0x101401C0) == 0)) {
        Debug("FIRM0 is corrupt (non critical)");
        Debug("(this is expected with a9lh)");
    } else if (firm_corruption) {
        if (firm_corruption == 0x3)
            Debug("FIRM0 and FIRM1 are corrupt");
        else
            Debug("FIRM%i is corrupt", (firm_corruption == 0x2) ? 1 : 0);
        FileClose();
        return 1;
    }
    
    FileClose();
    
    return 0;
}

u32 OutputFileNameSelector(char* filename, const char* basename, char* extension) {
    char bases[3][64] = { 0 };
    char* dotpos = NULL;
    
    // build first base name and extension
    strncpy(bases[0], basename, 63);
    dotpos = strrchr(bases[0], '.');
    
    if (dotpos) {
        *dotpos = '\0';
        if (!extension)
            extension = dotpos + 1;
    }
    
    // build other two base names
    snprintf(bases[1], 63, "%s_%s", bases[0], (emunand_header) ? "emu" : "sys");
    snprintf(bases[2], 63, "%s%s" , (emunand_header) ? "emu" : "sys", bases[0]);
    
    u32 fn_id = (emunand_header) ? 1 : 0;
    u32 fn_num = (emunand_header) ? (emunand_offset / EMUNAND_MULTI_SECTORS) : 0;
    bool exists = false;
    char extstr[16] = { 0 };
    if (extension)
        snprintf(extstr, 15, ".%s", extension);
    Debug("Use arrow keys and <A> to choose a name");
    while (true) {
        char numstr[2] = { 0 };
        // build and output file name (plus "(!)" if existing)
        numstr[0] = (fn_num > 0) ? '0' + fn_num : '\0';
        snprintf(filename, 63, "%s%s%s", bases[fn_id], numstr, extstr);
        if ((exists = FileOpen(filename)))
            FileClose();
        Debug("\r%s%s", filename, (exists) ? " (!)" : "");
        // user input routine
        u32 pad_state = InputWait();
        if (pad_state & BUTTON_DOWN) { // increment filename id
            fn_id = (fn_id + 1) % 3;
        } else if (pad_state & BUTTON_UP) { // decrement filename id
            fn_id = (fn_id > 0) ? fn_id - 1 : 2;
        } else if ((pad_state & BUTTON_RIGHT) && (fn_num < 9)) { // increment number
            fn_num++;
        } else if ((pad_state & BUTTON_LEFT) && (fn_num > 0)) { // decrement number
            fn_num--;
        } else if (pad_state & BUTTON_A) {
            Debug("%s%s", filename, (exists) ? " (!)" : "");
            break;
        } else if (pad_state & BUTTON_B) {
            Debug("(cancelled by user)");
            return 2;
        }
    }
    
    // overwrite confirmation
    if (exists) {
        Debug("Press <A> to overwrite existing file");
        while (true) {
            u32 pad_state = InputWait();
            if (pad_state & BUTTON_A) {
                break;
            } else if (pad_state & BUTTON_B) {
                Debug("(cancelled by user)");
                return 2;
            }
        }
    }
    
    return 0;
}

u32 InputFileNameSelector(char* filename, const char* basename, char* extension, u8* magic, u32 msize, u32 fsize, bool accept_bigger) {
    char** fnptr = (char**) 0x20400000; // allow using 0x8000 byte
    char* fnlist = (char*) 0x20408000; // allow using 0x80000 byte
    u32 n_names = 0;
    
    // get base name, extension
    char base[64] = { 0 };
    if (basename != NULL) {
        // build base name and extension
        strncpy(base, basename, 63);
        char* dotpos = strrchr(base, '.');
        if (dotpos) {
            *dotpos = '\0';
            if (!extension)
                extension = dotpos + 1;
        }
    }
    
    // limit magic number size
    if (msize > 0x200)
        msize = 0x200;
    
    // pass #1 -> work dir
    // pass #2 -> root dir
    for (u32 i = 0; i < 2; i++) {
        // get the file list - try work directory first
        if (!GetFileList((i) ? "/" : WORK_DIR, fnlist, 0x80000, false, true, false))
            continue;
        
        // parse the file names list for usable entries
        for (char* fn = strtok(fnlist, "\n"); fn != NULL; fn = strtok(NULL, "\n")) {
            u8 data[0x200];
            char* dotpos = strrchr(fn, '.');
            if (strrchr(fn, '/'))
                fn = strrchr(fn, '/') + 1;
            if (strnlen(fn, 128) > 63)
                continue; // file name too long
            if ((basename != NULL) && !strcasestr(fn, base))
                continue; // basename check failed
            if ((extension != NULL) && (dotpos != NULL) && (strncasecmp(dotpos + 1, extension, strnlen(extension, 16))))
                continue; // extension check failed
            else if ((extension == NULL) != (dotpos == NULL))
                continue; // extension check failed
            if (!FileOpen(fn))
                continue; // file can't be opened
            if (fsize && (FileGetSize() < fsize)) {
                FileClose();
                continue; // file minimum size check failed
            } else if (fsize && !accept_bigger && (FileGetSize() != fsize)) {
                FileClose();
                continue; // file exact size check failed
            }
            if (msize) {
                if (FileRead(data, msize, 0) != msize) {
                    FileClose();
                    continue; // can't be read
                }
                if (memcmp(data, magic, msize) != 0) {
                    FileClose();
                    continue; // magic number does not match
                }
            }
            FileClose();
            // this is a match - keep it
            fnptr[n_names++] = fn;
            if (n_names * sizeof(char**) >= 0x8000)
                return 1;
        }
        if (n_names)
            break;
    }
    if (n_names == 0) {
        Debug("No usable file found");
        return 1;
    }
    
    u32 index = 0;
    Debug("Use arrow keys and <A> to choose a file");
    while (true) {
        snprintf(filename, 63, "%s", fnptr[index]);
        Debug("\r%s", filename);
        u32 pad_state = InputWait();
        if (pad_state & BUTTON_DOWN) { // next filename
            index = (index + 1) % n_names;
        } else if (pad_state & BUTTON_UP) { // previous filename
            index = (index > 0) ? index - 1 : n_names - 1;
        } else if (pad_state & BUTTON_A) {
            Debug("%s", filename);
            break;
        } else if (pad_state & BUTTON_B) {
            Debug("(cancelled by user)");
            return 2;
        }
    }
    
    return 0;
}

PartitionInfo* GetPartitionInfo(u32 partition_id)
{
    u32 partition_num = 0;
    
    if (partition_id == P_CTRNAND) {
        partition_num = (GetUnitPlatform() == PLATFORM_3DS) ? 5 : (CheckNandHeader(NULL) == NAND_HDR_N3DS) ? 6 : 7;
    } else {
        for(; !(partition_id & (1<<partition_num)) && (partition_num < 32); partition_num++);
    }
    
    return (partition_num >= 32) ? NULL : &(partitions[partition_num]);
}

u32 CtrNandPadgen(u32 param)
{
    (void) (param); // param is unused here
    u32 keyslot;
    u32 nand_size;

    // legacy sizes & offset, to work with 3DSFAT16Tool
    if (GetUnitPlatform() == PLATFORM_3DS) {
        keyslot = 0x4;
        nand_size = 758;
    } else {
        keyslot = 0x5;
        nand_size = 1055;
    }

    Debug("Creating NAND FAT16 xorpad. Size (MB): %u", nand_size);
    Debug("Filename: nand.fat16.xorpad");

    PadInfo padInfo = {
        .keyslot = keyslot,
        .setKeyY = 0,
        .size_mb = nand_size,
        .filename = "nand.fat16.xorpad",
        .mode = AES_CNT_CTRNAND_MODE
    };
    if(GetNandCtr(padInfo.ctr, 0xB930000) != 0)
        return 1;

    return CreatePad(&padInfo);
}

u32 TwlNandPadgen(u32 param)
{
    (void) (param); // param is unused here
    u32 size_mb = (partitions[0].size + (1024 * 1024) - 1) / (1024 * 1024);
    Debug("Creating TWLN FAT16 xorpad. Size (MB): %u", size_mb);
    Debug("Filename: twlnand.fat16.xorpad");

    PadInfo padInfo = {
        .keyslot = partitions[0].keyslot,
        .setKeyY = 0,
        .size_mb = size_mb,
        .filename = "twlnand.fat16.xorpad",
        .mode = AES_CNT_TWLNAND_MODE
    };
    if(GetNandCtr(padInfo.ctr, partitions[0].offset) != 0)
        return 1;

    return CreatePad(&padInfo);
}

u32 Firm0Firm1Padgen(u32 param)
{
    (void) (param); // param is unused here
    u32 size_mb = (partitions[3].size + partitions[4].size + (1024 * 1024) - 1) / (1024 * 1024);
    Debug("Creating FIRM0FIRM1 xorpad. Size (MB): %u", size_mb);
    Debug("Filename: firm0firm1.xorpad");

    PadInfo padInfo = {
        .keyslot = partitions[3].keyslot,
        .setKeyY = 0,
        .size_mb = size_mb,
        .filename = "firm0firm1.xorpad",
        .mode = AES_CNT_CTRNAND_MODE
    };
    if(GetNandCtr(padInfo.ctr, partitions[3].offset) != 0)
        return 1;

    return CreatePad(&padInfo);
}

u32 GetNandCtr(u8* ctr, u32 offset)
{
    static bool initial_setup_done = false;
    static u8 CtrNandCtr[16];
    static u8 TwlNandCtr[16];
    
    if (!initial_setup_done) {
        // calculate CTRNAND/TWL ctr from NAND CID
        u8 NandCid[16];
        u8 shasum[32];
        
        sdmmc_get_cid( 1, (uint32_t*) NandCid);
        sha_quick(shasum, NandCid, 16, SHA256_MODE);
        memcpy(CtrNandCtr, shasum, 16);
        
        sha_quick(shasum, NandCid, 16, SHA1_MODE);
        for(u32 i = 0; i < 16; i++) // little endian and reversed order
            TwlNandCtr[i] = shasum[15-i];
        
        initial_setup_done = true;
    }
    
    // get the correct CTR and increment counter
    memcpy(ctr, (offset >= 0x0B100000) ? CtrNandCtr : TwlNandCtr, 16);
    add_ctr(ctr, offset / 0x10);

    return 0;
}

u32 DecryptNandToMem(u8* buffer, u32 offset, u32 size, PartitionInfo* partition)
{
    CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = size, .buffer = buffer, .mode = partition->mode};
    if(GetNandCtr(info.ctr, offset) != 0)
        return 1;

    u32 n_sectors = (size + NAND_SECTOR_SIZE - 1) / NAND_SECTOR_SIZE;
    u32 start_sector = offset / NAND_SECTOR_SIZE;
    if (ReadNandSectors(start_sector, n_sectors, buffer) != 0) {
        Debug("%sNAND read error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }
    CryptBuffer(&info);

    return 0;
}

u32 DecryptNandToFile(const char* filename, u32 offset, u32 size, PartitionInfo* partition)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 result = 0;

    if (!DebugCheckFreeSpace(size))
        return 1;
    
    if (!DebugFileCreate(filename, true))
        return 1;

    for (u32 i = 0; i < size; i += NAND_SECTOR_SIZE * SECTORS_PER_READ) {
        u32 read_bytes = min(NAND_SECTOR_SIZE * SECTORS_PER_READ, (size - i));
        ShowProgress(i, size);
        if ((DecryptNandToMem(buffer, offset + i, read_bytes, partition) != 0) ||
            !DebugFileWrite(buffer, read_bytes, i)) {
            result = 1;
            break;
        }
    }

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 DumpNand(u32 param)
{
    char filename[64];
    u8* buffer = BUFFER_ADDRESS;
    u32 nand_size = (param & NB_MINSIZE) ? NAND_MIN_SIZE : getMMCDevice(0)->total_size * NAND_SECTOR_SIZE;
    u32 result = 0;
    
    
    // check actual EmuNAND size
    if (emunand_header && (emunand_offset + getMMCDevice(0)->total_size > NumHiddenSectors()))
        nand_size = NAND_MIN_SIZE;
    
    Debug("Dumping %sNAND. Size (MB): %u", (param & N_EMUNAND) ? "Emu" : "Sys", nand_size / (1024 * 1024));
    
    if (!DebugCheckFreeSpace(nand_size))
        return 1;
    
    if (OutputFileNameSelector(filename, (param & NB_MINSIZE) ? "NANDmin.bin" : "NAND.bin", NULL) != 0)
        return 1;
    if (!DebugFileCreate(filename, true))
        return 1;

    u32 n_sectors = nand_size / NAND_SECTOR_SIZE;
    for (u32 i = 0; i < n_sectors; i += SECTORS_PER_READ) {
        u32 read_sectors = min(SECTORS_PER_READ, (n_sectors - i));
        ShowProgress(i, n_sectors);
        if (ReadNandSectors(i, read_sectors, buffer) != 0)  {
            Debug("%sNAND read error", (emunand_header) ? "Emu" : "Sys");
            result = 1;
            break;
        }
        if (!DebugFileWrite(buffer, NAND_SECTOR_SIZE * read_sectors, i * NAND_SECTOR_SIZE)) {
            result = 1;
            break;
        }
    }

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 DecryptNandPartition(u32 param)
{
    PartitionInfo* p_info = NULL;
    char filename[64];
    u8 magic[NAND_SECTOR_SIZE];
    
    for (u32 partition_id = P_TWLN; partition_id <= P_CTRNAND; partition_id = partition_id << 1) {
        if (param & partition_id) {
            p_info = GetPartitionInfo(partition_id);
            break;
        }
    }
    if (p_info == NULL)
        return 1;
    
    Debug("Dumping & Decrypting %s, size (MB): %u", p_info->name, p_info->size / (1024 * 1024));
    if (DecryptNandToMem(magic, p_info->offset, 16, p_info) != 0)
        return 1;
    if ((p_info->magic[0] != 0xFF) && (memcmp(p_info->magic, magic, 8) != 0)) {
        Debug("Corrupt partition or decryption error");
        if (p_info->keyslot == 0x05)
            Debug("(or slot0x05keyY not set up)");
        return 1;
    }
    if (OutputFileNameSelector(filename, p_info->name, "bin") != 0)
        return 1;
    
    return DecryptNandToFile(filename, p_info->offset, p_info->size, p_info);
}

u32 EncryptMemToNand(u8* buffer, u32 offset, u32 size, PartitionInfo* partition)
{
    CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = size, .buffer = buffer, .mode = partition->mode};
    if(GetNandCtr(info.ctr, offset) != 0)
        return 1;

    u32 n_sectors = (size + NAND_SECTOR_SIZE - 1) / NAND_SECTOR_SIZE;
    u32 start_sector = offset / NAND_SECTOR_SIZE;
    CryptBuffer(&info);
    if (WriteNandSectors(start_sector, n_sectors, buffer) != 0) {
        Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }

    return 0;
}

u32 EncryptFileToNand(const char* filename, u32 offset, u32 size, PartitionInfo* partition)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 result = 0;

    if (!DebugFileOpen(filename))
        return 1;
    
    if (FileGetSize() != size) {
        Debug("%s has wrong size", filename);
        FileClose();
        return 1;
    }

    for (u32 i = 0; i < size; i += NAND_SECTOR_SIZE * SECTORS_PER_READ) {
        u32 read_bytes = min(NAND_SECTOR_SIZE * SECTORS_PER_READ, (size - i));
        ShowProgress(i, size);
        if (!DebugFileRead(buffer, read_bytes, i) ||
            (EncryptMemToNand(buffer, offset + i, read_bytes, partition) != 0)) {
            result = 1;
            break;
        }
    }

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 RestoreNand(u32 param)
{
    char filename[64];
    u8* buffer = BUFFER_ADDRESS;
    u32 nand_size = getMMCDevice(0)->total_size * NAND_SECTOR_SIZE;
    u32 result = 0;

    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
        
    // user file select
    if (InputFileNameSelector(filename, "NAND.bin", NULL, NULL, 0, NAND_MIN_SIZE, true) != 0)
        return 1;
    
    // safety checks
    if (!(param & NR_NOCHECKS)) {
        Debug("Validating NAND dump %s...", filename);
        if (CheckNandDumpIntegrity(filename) != 0)
            return 1;
    }
    
    // check EmuNAND partition size
    if (emunand_header) {
        if (((NumHiddenSectors() - emunand_offset) * NAND_SECTOR_SIZE < NAND_MIN_SIZE) || (NumHiddenSectors() < emunand_header)) {
            Debug("Error: Not enough space in EmuNAND partition");
            return 1; // this really should not happen
        } else if (emunand_offset + getMMCDevice(0)->total_size > NumHiddenSectors()) {
            Debug("Small EmuNAND, using minimum size...");
            nand_size = NAND_MIN_SIZE;
        }
    }
    
    // open file, adjust size if required
    // NAND dump has at least min size (checked 2x at this point)
    if (!FileOpen(filename))
        return 1;
    if (FileGetSize() < nand_size) {
        Debug("Small NAND backup, using minimum size...");
        nand_size = NAND_MIN_SIZE;
    }
    
    Debug("Restoring %sNAND. Size (MB): %u", (param & N_EMUNAND) ? "Emu" : "Sys", nand_size / (1024 * 1024));

    u32 n_sectors = nand_size / NAND_SECTOR_SIZE;
    if (!(param & NR_KEEPA9LH)) { // standard, full restore
        for (u32 i = 0; i < n_sectors; i += SECTORS_PER_READ) {
            u32 read_sectors = min(SECTORS_PER_READ, (n_sectors - i));
            ShowProgress(i, n_sectors);
            if (!DebugFileRead(buffer, NAND_SECTOR_SIZE * read_sectors, i * NAND_SECTOR_SIZE)) {
                result = 1;
                break;
            }
            if (WriteNandSectors(i, read_sectors, buffer) != 0) {
                Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
                result = 1;
                break;
            }
        }
    } else { // ARM9loaderhax preserving restore
        for (u32 section = 0; section < 3; section++) {
            u32 start_sector, end_sector;
            if (section == 0) { // NAND header
                start_sector = 0;
                end_sector = 1;
            } else if (section == 1) { // TWLN, TWLP & AGBSAVE
                start_sector = partitions[0].offset / NAND_SECTOR_SIZE;
                end_sector = ((partitions[2].offset + partitions[2].size) - partitions[0].offset) / NAND_SECTOR_SIZE;
            } else { // CTRNAND (full size) (FIRM skipped)
                start_sector = 0x0B930000 / NAND_SECTOR_SIZE;
                end_sector = n_sectors;
            }
            for (u32 i = start_sector; i < end_sector; i += SECTORS_PER_READ) {
                u32 read_sectors = min(SECTORS_PER_READ, (end_sector - i));
                ShowProgress(i, n_sectors);
                if (!DebugFileRead(buffer, NAND_SECTOR_SIZE * read_sectors, i * NAND_SECTOR_SIZE)) {
                    result = 1;
                    break;
                }
                if (WriteNandSectors(i, read_sectors, buffer) != 0) {
                    Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
                    result = 1;
                    break;
                }
            }
        }
    }

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 InjectNandPartition(u32 param)
{
    PartitionInfo* p_info = NULL;
    char filename[64];
    u8 magic[NAND_SECTOR_SIZE];
    
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
    
    for (u32 partition_id = P_TWLN; partition_id <= P_CTRNAND; partition_id = partition_id << 1) {
        if (param & partition_id) {
            p_info = GetPartitionInfo(partition_id);
            break;
        }
    }
    if (p_info == NULL)
        return 1;
    
    Debug("Encrypting & Injecting %s, size (MB): %u", p_info->name, p_info->size / (1024 * 1024));
    // User file select
    if (InputFileNameSelector(filename, p_info->name, "bin",
        p_info->magic, (p_info->magic[0] != 0xFF) ? 8 : 0, p_info->size, false) != 0)
        return 1;
    
    // Encryption check
    if (DecryptNandToMem(magic, p_info->offset, 16, p_info) != 0)
        return 1;
    if ((p_info->magic[0] != 0xFF) && (memcmp(p_info->magic, magic, 8) != 0)) {
        Debug("Corrupt partition or decryption error");
        if (p_info->keyslot == 0x05)
            Debug("(or slot0x05keyY not set up)");
        return 1;
    }
    
    // File check
    if (FileGetData(filename, magic, 8, 0) == 8) {
        if ((p_info->magic[0] != 0xFF) && (memcmp(p_info->magic, magic, 8) != 0)) {
            Debug("Bad file content, won't inject");
            return 1;
        }
    } else {
        Debug("File is too small, won't inject");
        return 1;
    }
    
    return EncryptFileToNand(filename, p_info->offset, p_info->size, p_info);
}

u32 ValidateNandDump(u32 param)
{
    (void) (param); // param is unused here
    char filename[64];
        
    // user file select
    if (InputFileNameSelector(filename, "NAND.bin", NULL, NULL, 0, NAND_MIN_SIZE, true) != 0)
        return 1;
    Debug("Validating NAND dump %s...", filename);
    if (CheckNandDumpIntegrity(filename) != 0)
        return 1;
    
    return 0;
}

uint64_t bswap64(uint64_t a)
{
  a = ((a & 0x00000000000000FFULL) << 56) | 
      ((a & 0x000000000000FF00ULL) << 40) | 
      ((a & 0x0000000000FF0000ULL) << 24) | 
      ((a & 0x00000000FF000000ULL) <<  8) | 
      ((a & 0x000000FF00000000ULL) >>  8) | 
      ((a & 0x0000FF0000000000ULL) >> 24) | 
      ((a & 0x00FF000000000000ULL) >> 40) | 
      ((a & 0xFF00000000000000ULL) >> 56);
  return a;
}

u32 DumpAgbSave(u32 parm)
{
    PartitionInfo* p_info = GetPartitionInfo(P_AGBSAVE);
    u8 Header[NAND_SECTOR_SIZE];
    DecryptNandToMem(Header, p_info->offset, NAND_SECTOR_SIZE, p_info);
    u32 Saveadder;
    memcpy(&Saveadder, Header + (sizeof(u8) * 0x50), sizeof(u32));
    char *Magic = ".SAV";
    if (Saveadder != 0x200 || memcmp(Magic, Header, 4)) {
        Debug("The Agb_save partiton is corrupted.");
        Debug("Did you run an Agb_firm game?");
        return 1;
    }
    u32 Savesize;
    memcpy(&Savesize, Header + (sizeof(u8) * 0x54), sizeof(u32));
    u32 Titleid;
    memcpy(&Titleid, Header + 0x38, 4);
    Debug("Title id %08x", Titleid);
    if (Savesize == 32768) {
        Debug("Use save type 0");
    } else if (Savesize == 65536) {
	Debug("Use save type 1");
    } else if (Savesize == 0x2000) {
	Debug("Use save type 2");
    } else {
        Debug("Injecton support for this game is not yet ready");
    }
    if (Savesize == 0x2000) {
        u8* buffer = BUFFER_ADDRESS;
        int x;
        DecryptNandToMem(buffer, p_info->offset + Saveadder, Savesize, p_info);
        u64 *u64_buffer = (u64 *)buffer;
        for(x = 0; x <= Savesize / 8; x++) {
            u64_buffer[x] = bswap64(u64_buffer[x]);
        }
        DebugFileCreate("agb_dump.sav", true);
        DebugFileWrite(buffer, Savesize, 0);
        return 0;
    } else {
        return DecryptNandToFile("agb_dump.sav", p_info->offset + Saveadder, Savesize, p_info);
    }
}