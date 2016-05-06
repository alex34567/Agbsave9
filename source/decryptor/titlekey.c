#include "fs.h"
#include "draw.h"
#include "platform.h"
#include "decryptor/aes.h"
#include "decryptor/decryptor.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"
#include "decryptor/titlekey.h"

// From https://github.com/profi200/Project_CTR/blob/master/makerom/pki/prod.h#L19
static const u8 common_keyy[6][16] = {
    {0xD0, 0x7B, 0x33, 0x7F, 0x9C, 0xA4, 0x38, 0x59, 0x32, 0xA2, 0xE2, 0x57, 0x23, 0x23, 0x2E, 0xB9} , // 0 - eShop Titles
    {0x0C, 0x76, 0x72, 0x30, 0xF0, 0x99, 0x8F, 0x1C, 0x46, 0x82, 0x82, 0x02, 0xFA, 0xAC, 0xBE, 0x4C} , // 1 - System Titles
    {0xC4, 0x75, 0xCB, 0x3A, 0xB8, 0xC7, 0x88, 0xBB, 0x57, 0x5E, 0x12, 0xA1, 0x09, 0x07, 0xB8, 0xA4} , // 2
    {0xE4, 0x86, 0xEE, 0xE3, 0xD0, 0xC0, 0x9C, 0x90, 0x2F, 0x66, 0x86, 0xD4, 0xC0, 0x6F, 0x64, 0x9F} , // 3
    {0xED, 0x31, 0xBA, 0x9C, 0x04, 0xB0, 0x67, 0x50, 0x6C, 0x44, 0x97, 0xA3, 0x5B, 0x78, 0x04, 0xFC} , // 4
    {0x5E, 0x66, 0x99, 0x8A, 0xB4, 0xE8, 0x93, 0x16, 0x06, 0x85, 0x0F, 0xD7, 0xA1, 0x6D, 0xD7, 0x55} , // 5
};


u32 CryptTitlekey(TitleKeyEntry* entry, bool encrypt)
{
    CryptBufferInfo info = {.keyslot = 0x3D, .setKeyY = 1, .size = 16, .buffer = entry->titleKey,
        .mode = encrypt ? AES_CNT_TITLEKEY_ENCRYPT_MODE : AES_CNT_TITLEKEY_DECRYPT_MODE};
    memset(info.ctr, 0, 16);
    memcpy(info.ctr, entry->titleId, 8);
    memcpy(info.keyY, (void *)common_keyy[entry->commonKeyIndex], 16);
    
    CryptBuffer(&info);
    
    return 0;
}

u32 CryptTitlekeysFile(u32 param)
{
    EncKeysInfo *info = (EncKeysInfo*)0x20316000;
    char filename[64];

    if (InputFileNameSelector(filename, (param & TK_ENCRYPTED) ? "decTitleKeys.bin" : "encTitleKeys.bin",
        NULL, NULL, 0, 16, true) != 0)
        return 1;
    
    if (!DebugFileOpen(filename))
        return 1;
    
    if (!DebugFileRead(info, 16, 0)) {
        FileClose();
        return 1;
    }

    if (!info->n_entries || info->n_entries > MAX_ENTRIES) {
        Debug("Too many/few entries specified: %i", info->n_entries);
        FileClose();
        return 1;
    }

    Debug("Number of entries: %i", info->n_entries);
    if (!DebugFileRead(info->entries, info->n_entries * sizeof(TitleKeyEntry), 16)) {
        FileClose();
        return 1;
    }
    
    FileClose();

    Debug("%scrypting Title Keys...", (param & TK_ENCRYPTED) ? "En" : "De");
    for (u32 i = 0; i < info->n_entries; i++)
        CryptTitlekey(&(info->entries[i]), (param & TK_ENCRYPTED));

    if (OutputFileNameSelector(filename, (param & TK_ENCRYPTED) ? "encTitleKeys.bin" : "decTitleKeys.bin", NULL) != 0)
        return 1;
    if (!DebugFileCreate(filename, true))
        return 1;
    if (!DebugFileWrite(info, info->n_entries * sizeof(TitleKeyEntry) + 16, 0)) {
        FileClose();
        return 1;
    }
    FileClose();

    return 0;
}

u32 DumpTitlekeysNand(u32 param)
{
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);;
    u8* buffer = BUFFER_ADDRESS;
    EncKeysInfo *info = (EncKeysInfo*) 0x20316000;
    char filename[64];
    
    u32 nKeys = 0;
    u32 nSkipped = 0;
    u32 offset = 0;
    u32 size = 0;
    
    Debug("Searching for ticket.db...");
    if (SeekFileInNand(&offset, &size, "DBS        TICKET  DB ", ctrnand_info) != 0) {
        Debug("Failed!");
        return 1;
    }
    Debug("Found at %08X, size %uMB", offset, size / (1024 * 1024));
    
    Debug("%s Title Keys...", (param & TK_ENCRYPTED) ? "Dumping" : "Decrypting");
    memset(info, 0, 0x10);
    for (u32 t_offset = 0; t_offset < size; t_offset += BUFFER_MAX_SIZE - NAND_SECTOR_SIZE) {
        u32 read_bytes = min(BUFFER_MAX_SIZE, (size - t_offset));
        ShowProgress(t_offset, size);
        if (DecryptNandToMem(buffer, offset + t_offset, read_bytes, ctrnand_info) != 0)
            return 1;
        for (u32 i = 0; i < read_bytes - NAND_SECTOR_SIZE; i++) {
            if(memcmp(buffer + i, (u8*) "Root-CA00000003-XS0000000c", 26) == 0) {
                u32 exid;
                u32 consoleId = getle32(buffer + i + 0x98);
                u8* titleId = buffer + i + 0x9C;
                u32 commonKeyIndex = *(buffer + i + 0xB1);
                u8* titlekey = buffer + i + 0x7F;
                for (exid = 0; exid < nKeys; exid++)
                    if (memcmp(titleId, info->entries[exid].titleId, 8) == 0)
                        break;
                if (!consoleId || (exid < nKeys)) {
                    nSkipped++;
                    continue; // skip useless / duplicates
                }
                memset(&(info->entries[nKeys]), 0, sizeof(TitleKeyEntry));
                memcpy(info->entries[nKeys].titleId, titleId, 8);
                memcpy(info->entries[nKeys].titleKey, titlekey, 16);
                info->entries[nKeys].commonKeyIndex = commonKeyIndex;
                if (!(param & TK_ENCRYPTED))
                    CryptTitlekey(&(info->entries[nKeys]), false);
                nKeys++;
            }
        }
        if (nKeys == MAX_ENTRIES) {
            Debug("Maximum number of titlekeys found");
            break;
        }
    }
    info->n_entries = nKeys;
    ShowProgress(0, 0);
    
    Debug("Decrypted %u unique Titlekeys", nKeys);
    Debug("Skipped %u useless Titlekeys", nSkipped);
    
    if (OutputFileNameSelector(filename, (param & TK_ENCRYPTED) ? "encTitleKeys.bin" : "decTitleKeys.bin", NULL) != 0)
        return 1;
    
    if(nKeys > 0) {
        if (!DebugFileCreate(filename, true))
            return 1;
        if (!DebugFileWrite(info, 0x10 + nKeys * 0x20, 0)) {
            FileClose();
            return 1;
        }
        FileClose();
    } else {
        return 1;
    }

    return 0;
}
