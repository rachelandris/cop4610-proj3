#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <sys/stat.h>
#include <stdbool.h>

#define MAX_PATH_LENGTH 256
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define ATTR_LONG_NAME 0x0F // For long names
#define MAX_OPEN_FILES 10 //open files max

FILE *image = NULL;

// FAT32 boot sector structure
typedef struct {
    uint32_t root_cluster;
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint32_t total_clusters;
    uint32_t entries_per_fat;
    size_t image_size;
    uint32_t reserved_sectors;
    uint32_t fat_count;
    uint32_t fat_size;
} FAT32_Info;

// Directory entry structure for FAT32 (packed to avoid padding)
typedef struct __attribute__((packed)) {
    char name[11];              // 8.3 format 
    uint8_t attributes;         // File attributes (e.g., directory, archive)
    uint16_t first_cluster_hi;  // High 16 bits of the starting cluster
    uint16_t first_cluster_lo;  // Low 16 bits of the starting cluster
} FAT32_DirectoryEntry;

uint32_t current_cluster;  // Tracks the current working directory cluster
char current_dir_name[MAX_PATH_LENGTH] = "";  // Holds the current directory path
 
typedef struct {
    char name[12];       // 8.3 format (11 bytes + null terminator)
    uint32_t first_cluster; // First cluster of the file
    uint32_t offset;     // Current offset within the file
    char mode[3];        // Mode: "r", "w", "rw", "wr"
    uint32_t size;	//this is new
} OpenedFile;

OpenedFile open_files[MAX_OPEN_FILES]; // Array to store open files
int open_file_count = 0;              // Number of currently opened files

// Parse the boot sector and extract necessary info for FAT32 file system
FAT32_Info parse_boot_sector(FILE *image) {
    FAT32_Info info;
    uint8_t boot_sector[512];

    fread(boot_sector, sizeof(uint8_t), 512, image);

    info.bytes_per_sector = boot_sector[0x0B] | (boot_sector[0x0C] << 8);
    info.sectors_per_cluster = boot_sector[0x0D];
    info.root_cluster = boot_sector[0x2C] | (boot_sector[0x2D] << 8) | (boot_sector[0x2E] << 16) | (boot_sector[0x2F] << 24);
    info.reserved_sectors = boot_sector[0x0E] | (boot_sector[0x0F] << 8);
    info.fat_count = boot_sector[0x10];
    info.fat_size = boot_sector[0x24] | (boot_sector[0x25] << 8) | (boot_sector[0x26] << 16) | (boot_sector[0x27] << 24);

    uint32_t total_sectors = boot_sector[0x20] | (boot_sector[0x21] << 8) | (boot_sector[0x22] << 16) | (boot_sector[0x23] << 24);
    uint32_t data_sectors = total_sectors - (info.reserved_sectors + info.fat_count * info.fat_size);
    info.total_clusters = data_sectors / info.sectors_per_cluster;
    info.entries_per_fat = info.fat_size * info.bytes_per_sector / 4;

    fseek(image, 0, SEEK_END);
    info.image_size = ftell(image);
    fseek(image, 0, SEEK_SET);

    return info;
}

void print_info(const FAT32_Info *info) {
    printf("Root cluster: %u\n", info->root_cluster);
    printf("Bytes per sector: %u\n", info->bytes_per_sector);
    printf("Sectors per cluster: %u\n", info->sectors_per_cluster);
    printf("Total clusters in data region: %u\n", info->total_clusters);
    printf("Entries per FAT: %u\n", info->entries_per_fat);
    printf("Size of image: %zu bytes\n", info->image_size);
}


uint32_t get_next_cluster(FILE *image, const FAT32_Info *info, uint32_t cluster) {
    if (cluster < 2 || cluster > 0x0FFFFFFF) {
        fprintf(stderr, "Invalid cluster number: %u\n", cluster);
        return 0x0FFFFFFF; // End of chain or invalid cluster
    }

    uint32_t fat_offset = cluster * 4; // Each FAT entry is 4 bytes
    uint32_t fat_sector = info->reserved_sectors + (fat_offset / info->bytes_per_sector);
    uint32_t fat_entry_offset = fat_offset % info->bytes_per_sector;

    uint8_t fat_buffer[info->bytes_per_sector];
    fseek(image, fat_sector * info->bytes_per_sector, SEEK_SET);
    fread(fat_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

    // Extract the 32-bit FAT entry manually
    uint32_t raw_fat_entry = fat_buffer[fat_entry_offset] |
                             (fat_buffer[fat_entry_offset + 1] << 8) |
                             (fat_buffer[fat_entry_offset + 2] << 16) |
                             (fat_buffer[fat_entry_offset + 3] << 24);

    uint32_t next_cluster = raw_fat_entry & 0x0FFFFFFF; // Get the next cluster from FAT

    if (next_cluster >= 0x0FFFFFF8 || next_cluster == 0x00000000) {
        return 0x0FFFFFFF; // End of chain
    }
    return next_cluster;
}


uint32_t find_free_cluster(FILE *image, const FAT32_Info *info) {

    uint32_t fat_table_start = info->reserved_sectors * info->bytes_per_sector; //start of img table
    uint32_t total_sectors = info->image_size / info->bytes_per_sector; //total sectors in the disk image (image size divided by bytes per sector)
    uint32_t fat_table_size = info->fat_count * info->fat_size; //total size of the FAT tables
    
    uint32_t total_clusters = info->total_clusters; //total clusters already available in the FAT32_Info structure
    
    uint32_t fat_entry_size = 4;  //4 bytes

    //iterate over the FAT entries starting from the second cluster
    for (uint32_t cluster = 2; cluster < total_clusters; cluster++) {
        uint32_t fat_entry_offset = fat_table_start + (cluster * fat_entry_size); // Calculate the FAT entry offset for the cluster
        uint32_t fat_entry = 0;

        //read current cluster fat entry
        fseek(image, fat_entry_offset, SEEK_SET);
        fread(&fat_entry, sizeof(fat_entry), 1, image);

        //check if the cluster is free
        if (fat_entry == 0x00000000) {
            return cluster;  // Return the first free cluster found
        }
    }

    return 0x0FFFFFFF;  //no free clusters found
}

void parse_quoted_argument(const char *command, char *output) { 
    const char *start = strchr(command, '"');
    const char *end = strrchr(command, '"');
    if (start && end && start != end) {
        size_t length = end - start - 1;
        strncpy(output, start + 1, length);
        output[length] = '\0';
    } else {
        // Handle unquoted argument
        if (command && *command != '\0') {
            strncpy(output, command, MAX_PATH_LENGTH);
            output[MAX_PATH_LENGTH - 1] = '\0';  // Ensure null-termination
        } else {
            output[0] = '\0';  // Invalid argument
        }
    }
}

void allocate_cluster(FILE *image, const FAT32_Info *info, uint32_t cluster, uint32_t value) {
    uint32_t fat_offset = cluster * sizeof(uint32_t);
    uint32_t fat_sector = info->reserved_sectors + (fat_offset / info->bytes_per_sector);
    uint32_t fat_entry_offset = fat_offset % info->bytes_per_sector;

    //printf("[DEBUG] allocate_cluster: FAT offset: %u, FAT sector: %u, FAT entry offset: %u\n", 
           //fat_offset, fat_sector, fat_entry_offset);

    uint8_t sector_buffer[info->bytes_per_sector];

    // Read the FAT sector into memory
    fseek(image, fat_sector * info->bytes_per_sector, SEEK_SET);
    size_t read_result = fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

    if (read_result != info->bytes_per_sector) {
        printf("[ERROR] Failed to read FAT sector %u\n", fat_sector);
        return;
    }

    //little endian if needed
    value = htole32(value);

    // Update the FAT entry with the new value
    memcpy(&sector_buffer[fat_entry_offset], &value, sizeof(uint32_t));

    // Write the updated sector back to the FAT table
    fseek(image, fat_sector * info->bytes_per_sector, SEEK_SET);
    size_t write_result = fwrite(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

    if (write_result != info->bytes_per_sector) {
        printf("[ERROR] Failed to write FAT sector %u\n", fat_sector);
        return;
    }

    fflush(image); // Ensure the changes are committed to the image
    //printf("[DEBUG] Updated FAT entry for cluster %u to 0x%X\n", cluster, value);
}

//check if a file or directory exists
int check_if_exists(FILE *image, const FAT32_Info *info, const char *name) {
    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = current_cluster;

    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + info->reserved_sectors + (info->fat_count * info->fat_size);
        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

        int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
        for (int i = 0; i < entry_count; i++) {
            uint8_t *entry_start = &sector_buffer[i * sizeof(FAT32_DirectoryEntry)];
            char name_buffer[12] = {0};
            memcpy(name_buffer, entry_start, 11);

            if (name_buffer[0] == 0x00 || name_buffer[0] == 0xE5) continue;  //empty or deleted entries
            if (strcmp(name_buffer, name) == 0) {
                return 1;  //exists
            }
        }
        cluster = get_next_cluster(image, info, cluster);
    }

    return 0;  //dne
}

//Funstion to list contents of directory
void ls_command(FILE *image, const FAT32_Info *info) {
    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = current_cluster; // Use the current directory's starting cluster
    uint32_t first_data_sector = info->reserved_sectors + (info->fat_count * info->fat_size);

    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + first_data_sector;

        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

        int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);

        for (int i = 0; i < entry_count; i++) {
            FAT32_DirectoryEntry *entry = (FAT32_DirectoryEntry *)&sector_buffer[i * sizeof(FAT32_DirectoryEntry)];

            // Skip empty or deleted entries
            if (entry->name[0] == 0x00 || entry->name[0] == 0xE5) {
                continue;
            }

            char name[12] = {0};
            memcpy(name, entry->name, 11);
            for (int j = 10; j >= 0 && name[j] == ' '; j--) {
                name[j] = '\0';
            }

            //check to creat . and ..
           /* if (strcmp(name, ".") == 0) {
                printf("found '.' entry in directory %s\n", name);
            } else if (strcmp(name, "..") == 0) {
                printf("found '..' entry in directory %s\n", name);
            } */

            if (entry->attributes & ATTR_DIRECTORY) {
                printf("[DIR] %s\n", name);
            } else if (entry->attributes & ATTR_ARCHIVE) {
                printf("%s\n", name);
            }
        }

        cluster = get_next_cluster(image, info, cluster);
    }
}

uint32_t last; //to verify clusters
char global_path[256] = "/";  //idk if i use this
uint32_t parent_cluster = 0;  //THIS COULD DO WEIRD THINGS!!


//does not really work



// Function to get the cluster of a directory based on the full path
uint32_t get_cluster_from_path(FILE *image, const FAT32_Info *info, const char *path) {
    uint32_t cluster = 2;  // Start from the root directory
    uint32_t first_data_sector = info->reserved_sectors + (info->fat_count * info->fat_size);
    uint8_t sector_buffer[info->bytes_per_sector];
    char path_copy[256];
    strcpy(path_copy, path);
    
    //tokenize the path
    char *token = strtok(path_copy, "/");
    while (token != NULL) {
        bool found = false;
        while (cluster >= 2) {
            uint32_t sector = (cluster - 2) * info->sectors_per_cluster + first_data_sector;

            for (uint8_t i = 0; i < info->sectors_per_cluster; i++) {
                fseek(image, (sector + i) * info->bytes_per_sector, SEEK_SET);
                fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

                int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
                for (int j = 0; j < entry_count; j++) {
                    uint8_t *entry_start = &sector_buffer[j * sizeof(FAT32_DirectoryEntry)];

                    // Read and parse the directory entry
                    char name[12] = {0};
                    memcpy(name, entry_start, 11);

                    // Skip invalid or non-directory entries
                    if (name[0] == 0x00 || name[0] == 0xE5 || !(entry_start[11] & ATTR_DIRECTORY)) {
                        continue;
                    }

                    // Trim trailing spaces
                    for (int k = 10; k >= 0 && name[k] == ' '; k--) {
                        name[k] = '\0';
                    }

                    // Match the directory name
                    if (strcmp(name, token) == 0) {
                        uint16_t first_cluster_hi = entry_start[20] | (entry_start[21] << 8);
                        uint16_t first_cluster_lo = entry_start[26] | (entry_start[27] << 8);
                        cluster = (first_cluster_hi << 16) | first_cluster_lo;
                        found = true;
                        break;
                    }
                }

                if (found) {
                    break;
                }
            }

            if (found) {
                break;
            }

            // Move to the next cluster in the FAT chain
            cluster = get_next_cluster(image, info, cluster);
        }

        if (!found) {
            printf("Directory '%s' not found.\n", token);
            return 0;  // Directory not found
        }

        token = strtok(NULL, "/");
    }

    return cluster;
}

void cd_command(FILE *image, const FAT32_Info *info, const char *dirname) {
    uint32_t cluster = current_cluster;
    uint32_t first_data_sector = info->reserved_sectors + (info->fat_count * info->fat_size);
    uint8_t sector_buffer[info->bytes_per_sector];

    if (dirname == NULL || strlen(dirname) == 0) {
        printf("Error: Invalid directory name.\n");
        return;
    }

    // Handling ..
    if (strcmp(dirname, "..") == 0) {
        // Modify the global path by removing the last directory
        char *last_slash = strrchr(current_dir_name, '/');
        if (last_slash != NULL) {
            *last_slash = '\0';  // Remove the last directory from the path
        } else {
            strcpy(current_dir_name, "");  // Reset to root if no more slashes
        }

        // Now call get_cluster_from_path with the updated path
        uint32_t parent_cluster = get_cluster_from_path(image, info, current_dir_name);
        if (parent_cluster == 0) {
            printf("Error: Could not move to parent directory.\n");
            return;
        }

        // Update the current cluster to the parent directory's cluster
        current_cluster = parent_cluster;
        //printf("Moved Up. New Path: %s\n", current_dir_name);
        return;
    }

    // Navigate to the specified directory
    while (cluster >= 2) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + first_data_sector;

        for (uint8_t i = 0; i < info->sectors_per_cluster; i++) {
            fseek(image, (sector + i) * info->bytes_per_sector, SEEK_SET);
            fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

            int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
            for (int j = 0; j < entry_count; j++) {
                uint8_t *entry_start = &sector_buffer[j * sizeof(FAT32_DirectoryEntry)];

                // Read and parse the directory entry
                char name[12] = {0};
                memcpy(name, entry_start, 11);
                uint8_t attributes = entry_start[11];
                uint16_t first_cluster_hi = entry_start[20] | (entry_start[21] << 8);
                uint16_t first_cluster_lo = entry_start[26] | (entry_start[27] << 8);

                // Skip invalid or non-directory entries
                if (name[0] == 0x00 || name[0] == 0xE5 || !(attributes & ATTR_DIRECTORY)) {
                    continue;
                }

                // Trim trailing spaces from the name
                for (int k = 10; k >= 0 && name[k] == ' '; k--) {
                    name[k] = '\0';
                }

                // Check if the directory matches the target directory
                if (strcmp(name, dirname) == 0) {
                    uint32_t target_cluster = (first_cluster_hi << 16) | first_cluster_lo;

                    // Update current cluster to the target directory
                    current_cluster = target_cluster;
                    printf("Moved Into Subdirectory: %s\n", dirname);

                    // Update current directory path
                    if (strcmp(current_dir_name, "") == 0) {
                        snprintf(current_dir_name, sizeof(current_dir_name), "/%s", dirname);
                    } else {
                        // Append the subdirectory to the current path
                        strncat(current_dir_name, "/", sizeof(current_dir_name) - strlen(current_dir_name) - 1);
                        strncat(current_dir_name, dirname, sizeof(current_dir_name) - strlen(current_dir_name) - 1);
                    }

                    return;  // Success
                }
            }
        }

        // Move to the next cluster
        cluster = get_next_cluster(image, info, cluster);

        printf("Moving to Next Cluster: %u\n", cluster);
    }

    printf("Error: Directory '%s' not found.\n", dirname);
}

bool is_valid_cluster(uint32_t cluster) {
    // Check if the cluster is within the valid range
    if (cluster >= 2 && cluster <= 0x0FFFFFEF) {
        // Exclude any reserved or special values like bad clusters
        if (cluster != 0x0FFFFFF7) {
            return true;
        }
    }
    return false;
}
uint32_t get_fat_entry(FILE *image, const FAT32_Info *info, uint32_t cluster) { //CHECK IF USE
    uint32_t fat_offset = cluster * sizeof(uint32_t);
    uint32_t fat_sector = info->reserved_sectors + (fat_offset / info->bytes_per_sector);
    uint32_t fat_entry_offset = fat_offset % info->bytes_per_sector;

    //printf("[DEBUG] get_fat_entry: FAT offset: %u, FAT sector: %u, FAT entry offset: %u\n", 
           //fat_offset, fat_sector, fat_entry_offset);

    uint8_t sector_buffer[info->bytes_per_sector];

    // Read the FAT sector into memory
    fseek(image, fat_sector * info->bytes_per_sector, SEEK_SET);
    size_t read_result = fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

    if (read_result != info->bytes_per_sector) {
        printf("[ERROR] Failed to read FAT sector %u\n", fat_sector);
        return 0;
    }

    // Extract the FAT entry
    uint32_t value;
    memcpy(&value, &sector_buffer[fat_entry_offset], sizeof(uint32_t));
    return le32toh(value); // Convert from little-endian to host-endian
}

void mkdir_command(FILE *image, const FAT32_Info *info, const char *dirname) {
    printf("Creating Directory: %s\n", dirname);

    uint32_t free_cluster, first_cluster = 0;
    uint32_t sector;  // Declare sector variable

    //printf("[DEBUG] Current Cluster (Parent) for mkdir: %u\n", current_cluster);

    // Allocate a free cluster for the new directory
    do {
        free_cluster = find_free_cluster(image, info);
        //printf("[DEBUG] Searching for free cluster, found: %u\n", free_cluster);
        if (free_cluster == 0x0FFFFFFF) {
            printf("[ERROR] No Free Clusters Available.\n");
            return;
        }
    } while (!is_valid_cluster(free_cluster));

    //printf("[DEBUG] Allocated Cluster for New Directory: %u\n", free_cluster);
    first_cluster = free_cluster;

    // Mark the cluster as the end of the chain (FAT entry for the new directory)
    allocate_cluster(image, info, free_cluster, 0x0FFFFFFF);

    // Verify the FAT entry for the newly allocated directory cluster
    uint32_t fat_entry = get_fat_entry(image, info, free_cluster);
    //printf("[DEBUG] Direct read of FAT entry for cluster %u: %u\n", free_cluster, fat_entry);

    if (fat_entry != 0x0FFFFFFF) {
        printf("[ERROR] FAT entry for cluster %u is incorrect. Expected end of chain (0x0FFFFFFF), found: %u\n", free_cluster, fat_entry);
        return;
    } else {
        //printf("[DEBUG] FAT entry for cluster %u correctly points to end of chain (0x0FFFFFFF)\n", free_cluster);
    }

    // Prepare directory entry for the new directory
    FAT32_DirectoryEntry new_dir_entry = {0};
    memset(new_dir_entry.name, ' ', 11);
    strncpy((char *)new_dir_entry.name, dirname, strlen(dirname));
    new_dir_entry.attributes = ATTR_DIRECTORY;
    new_dir_entry.first_cluster_hi = htole16((free_cluster >> 16) & 0xFFFF);
    new_dir_entry.first_cluster_lo = htole16(free_cluster & 0xFFFF);

    //printf("New Directory Cluster: %x\n", free_cluster);
    //printf("First Cluster HI: %x, First Cluster LO: %x\n", new_dir_entry.first_cluster_hi, new_dir_entry.first_cluster_lo);

    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t new_dir_sector = (free_cluster - 2) * info->sectors_per_cluster +
                              info->reserved_sectors +
                              (info->fat_count * info->fat_size);

    //printf("[DEBUG] Calculated sector for new directory: %u\n", new_dir_sector);

    // Manually create '.' and '..' entries
    FAT32_DirectoryEntry dot_entry = {0}, dotdot_entry = {0};
    memset(dot_entry.name, ' ', 11);
    dot_entry.name[0] = '.';  // "." entry
    dot_entry.attributes = ATTR_DIRECTORY;
    dot_entry.first_cluster_hi = htole16((free_cluster >> 16) & 0xFFFF);
    dot_entry.first_cluster_lo = htole16(free_cluster & 0xFFFF);

    memset(dotdot_entry.name, ' ', 11);
    dotdot_entry.name[0] = '.'; // ".." entry
    dotdot_entry.name[1] = '.'; 
    dotdot_entry.attributes = ATTR_DIRECTORY;

    // Correctly set the parent directory cluster for ".."
    dotdot_entry.first_cluster_hi = htole16((current_cluster >> 16) & 0xFFFF);  // Parent cluster HI
    dotdot_entry.first_cluster_lo = htole16(current_cluster & 0xFFFF);  // Parent cluster LO

    // Clear the sector buffer for writing entries
    memset(sector_buffer, 0, info->bytes_per_sector);

    // Write '.' entry to the first 16 bytes of the sector
    memcpy(sector_buffer, &dot_entry, sizeof(FAT32_DirectoryEntry));
    //printf("[DEBUG] Writing '.' entry to sector %u at offset 0\n", new_dir_sector);

    // Write '..' entry to the next 16 bytes of the sector
    memcpy(sector_buffer + sizeof(FAT32_DirectoryEntry), &dotdot_entry, sizeof(FAT32_DirectoryEntry));
    //printf("[DEBUG] Writing '..' entry to sector %u at offset %lu\n", new_dir_sector, sizeof(FAT32_DirectoryEntry));

    // Write the sector buffer to disk
    fseek(image, new_dir_sector * info->bytes_per_sector, SEEK_SET);
    size_t write_result = fwrite(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);
    if (write_result != info->bytes_per_sector) {
        printf("[ERROR] Failed to write directory entries to sector %u\n", new_dir_sector);
        return;
    }

    // Verify the write
    fseek(image, new_dir_sector * info->bytes_per_sector, SEEK_SET);
    size_t read_result = fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);
    if (read_result != info->bytes_per_sector) {
        printf("[ERROR] Failed to read back sector after writing.\n");
        return;
    }

    FAT32_DirectoryEntry read_dot, read_dotdot;
    memcpy(&read_dot, sector_buffer, sizeof(FAT32_DirectoryEntry));
    memcpy(&read_dotdot, sector_buffer + sizeof(FAT32_DirectoryEntry), sizeof(FAT32_DirectoryEntry));

    //printf("[DEBUG] Read-back '.' entry: Name: %.11s, Attr: 0x%X, Cluster HI: 0x%X, Cluster LO: 0x%X\n",
           //read_dot.name, read_dot.attributes, read_dot.first_cluster_hi, read_dot.first_cluster_lo);

    //printf("[DEBUG] Read-back '..' entry: Name: %.11s, Attr: 0x%X, Cluster HI: 0x%X, Cluster LO: 0x%X\n",
           //read_dotdot.name, read_dotdot.attributes, read_dotdot.first_cluster_hi, read_dotdot.first_cluster_lo);

    fflush(image);

    //handling the parent directory
    uint8_t parent_sector_buffer[info->bytes_per_sector];
    uint32_t parent_cluster = current_cluster;
    bool entry_added = false;

    // Debugging before writing the new directory entry
    //printf("[DEBUG] Verifying Parent Directory before writing new directory entry\n");
    for (uint32_t offset = 0; offset < info->bytes_per_sector; offset += sizeof(FAT32_DirectoryEntry)) {
        FAT32_DirectoryEntry entry = {0};
        memcpy(&entry, parent_sector_buffer + offset, sizeof(FAT32_DirectoryEntry));

        /*printf("[DEBUG] Parent Entry: Name: %.11s, Attr: 0x%X, Cluster HI: 0x%X, Cluster LO: 0x%X\n",
               entry.name, entry.attributes, entry.first_cluster_hi, entry.first_cluster_lo);*/
    }

    // Search for a free directory entry in the parent directory
    while (!entry_added && parent_cluster != 0x0FFFFFFF && parent_cluster != 0) {
        sector = (parent_cluster - 2) * info->sectors_per_cluster +
                 info->reserved_sectors +
                 (info->fat_count * info->fat_size);

        //printf("[DEBUG] Searching for free entry in parent directory (Cluster: %u), Sector: %u...\n", parent_cluster, sector);
        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        size_t read_parent_result = fread(parent_sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);
        if (read_parent_result != info->bytes_per_sector) {
            //printf("[ERROR] Failed to read parent directory sector. fread return value: %ld\n", read_parent_result);
            return;
        }

        for (uint32_t offset = 0; offset < info->bytes_per_sector; offset += sizeof(FAT32_DirectoryEntry)) {
            FAT32_DirectoryEntry entry = {0};
            memcpy(&entry, parent_sector_buffer + offset, sizeof(FAT32_DirectoryEntry));

            // Check for empty entry in the parent directory
            if (entry.name[0] == 0x00 || entry.name[0] == 0xE5) { // Empty or deleted entry
                //printf("[DEBUG] Found empty entry at offset %u, writing new directory entry...\n", offset);
                memcpy(parent_sector_buffer + offset, &new_dir_entry, sizeof(FAT32_DirectoryEntry));
                fseek(image, sector * info->bytes_per_sector, SEEK_SET);
                size_t write_parent_result = fwrite(parent_sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);
                if (write_parent_result != info->bytes_per_sector) {
                    printf("[ERROR] Failed to write parent directory sector. fwrite return value: %ld\n", write_parent_result);
                    return;
                }
                fflush(image);

                entry_added = true;
                break;
            }
        }

        if (!entry_added) {
            parent_cluster = get_next_cluster(image, info, parent_cluster);
            //printf("[DEBUG] No empty entry found, moving to next cluster: %u\n", parent_cluster);
        }
    }

    if (!entry_added) {
        printf("[ERROR] Failed to update parent directory - No free space found.\n");
    } else {
        // Verify the parent directory after writing the new directory entry
        //printf("[DEBUG] Verifying Parent Directory after writing new directory entry\n");
        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        size_t read_parent_result = fread(parent_sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);
        if (read_parent_result != info->bytes_per_sector) {
            //printf("[ERROR] Failed to read parent directory sector after update. fread return value: %ld\n", read_parent_result);
            return;
        }

        // Print updated parent entries after the new directory is added
        for (uint32_t offset = 0; offset < info->bytes_per_sector; offset += sizeof(FAT32_DirectoryEntry)) {
            FAT32_DirectoryEntry entry = {0};
            memcpy(&entry, parent_sector_buffer + offset, sizeof(FAT32_DirectoryEntry));

            //printf(" Updated Parent Entry: Name: %.11s, Attr: 0x%X, Cluster HI: 0x%X, Cluster LO: 0x%X\n",
                 //  entry.name, entry.attributes, entry.first_cluster_hi, entry.first_cluster_lo);
        }
    }
}


//Function to freat file
void creat_command(FILE *image, const FAT32_Info *info, const char *filename) {
    // Check if a file or directory with the same name already exists
    uint32_t next_cluster = 0; 
    if (check_if_exists(image, info, filename)) {
        printf("Error: File or directory with name '%s' already exists.\n", filename);
        return;
    }

    // Find a free cluster to store the file's data
    uint32_t free_cluster = find_free_cluster(image, info);
    if (free_cluster == 0x0FFFFFFF) {
        printf("Error: No free clusters available to create the file.\n");
        return;
    }

    // Allocate the free cluster for the new file
    allocate_cluster(image, info, free_cluster,next_cluster);

    // Create the directory entry for the new file
    FAT32_DirectoryEntry new_file_entry = {0};

    // Truncate or pad the file name to fit in the 8.3 format (11 bytes)
    char truncated_name[12] = {0}; // 11 chars + null terminator
    int i;
    for (i = 0; i < 11 && filename[i] != '\0'; i++) {
        truncated_name[i] = filename[i];
    }

    // Copy the file name to the new directory entry manually (11 bytes for the 8.3 format)
    for (int j = 0; j < 11; j++) {
        new_file_entry.name[j] = truncated_name[j];
    }

    // Set the attributes (0x20 for archive file, 0x10 for directory, 0x01 for read-only)
    new_file_entry.attributes = ATTR_ARCHIVE;  // Mark as a regular file (not a directory)

    // Set the first cluster high and low to the allocated free cluster
    new_file_entry.first_cluster_hi = (free_cluster >> 16) & 0xFFFF;
    new_file_entry.first_cluster_lo = free_cluster & 0xFFFF;

    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = current_cluster; // Start with the current directory's cluster

    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + info->reserved_sectors + (info->fat_count * info->fat_size);
        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

        int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
        for (int i = 0; i < entry_count; i++) {
            uint8_t *entry_start = &sector_buffer[i * sizeof(FAT32_DirectoryEntry)];

            // Check for an empty or deleted directory entry
            if (entry_start[0] == 0x00 || entry_start[0] == 0xE5) {
                // Manually write the new file entry at this position
                for (int j = 0; j < 11; j++) {
                    entry_start[j] = new_file_entry.name[j];  // Name
                }
                entry_start[11] = new_file_entry.attributes;  // Attributes
                entry_start[12] = 0x00;  // Reserved byte
                entry_start[13] = 0x00;  // Reserved byte
                entry_start[14] = 0x00;  // Reserved byte
                entry_start[15] = 0x00;  // Reserved byte
                entry_start[16] = new_file_entry.first_cluster_hi & 0xFF;  // First Cluster High byte
                entry_start[17] = (new_file_entry.first_cluster_hi >> 8) & 0xFF; // First Cluster High byte
                entry_start[18] = new_file_entry.first_cluster_lo & 0xFF;  // First Cluster Low byte
                entry_start[19] = (new_file_entry.first_cluster_lo >> 8) & 0xFF;  // First Cluster Low byte

                // Write the updated sector back to the image
                fseek(image, sector * info->bytes_per_sector, SEEK_SET);
                if (fwrite(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image) != info->bytes_per_sector) {
                    printf("Error: Failed to write file entry back to the disk.\n");
                    return;
                }
                return;
            }
        }

        // Move to the next cluster in the chain (if necessary)
        cluster = get_next_cluster(image, info, cluster);
    }

    // If we reach here, it means we couldn't find an empty space for the file entry
    printf("Error: No space available for new file entry.\n");
}

//Function to see if file is open
int is_file_opened(const char *filename) { //helper function for open
    for (int i = 0; i < open_file_count; i++) {
        if (strcmp(open_files[i].name, filename) == 0) {
            return 1; // File is already opened
        }
    }
    return 0; // File is not opened
}

int is_valid_mode(const char *mode) { //helper function for open
    return (strcmp(mode, "-r") == 0 || strcmp(mode, "-w") == 0 ||
            strcmp(mode, "-rw") == 0 || strcmp(mode, "-wr") == 0);
}

//HELPER FUNCTION FOR LSEEK !!! 
uint32_t get_file_size(FILE *image, const FAT32_Info *info, uint32_t first_cluster) { 
    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = first_cluster;
    uint32_t file_size = 0;

    // Traverse the clusters of the file and sum up the sizes
    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + info->reserved_sectors + (info->fat_count * info->fat_size);
        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);


        file_size += info->bytes_per_sector;

        // Move to the next cluster
        cluster = get_next_cluster(image, info, cluster);
    }
    return file_size;
}

uint32_t get_file_size_from_entry(const uint8_t *entry_data) { //get size dynamically
    return *(uint32_t *)(entry_data + 28);
}

//Function to opens file
void open_command(FILE *image, const FAT32_Info *info, const char *filename, const char *flags) {
    // Validate mode
    if (!is_valid_mode(flags)) {
        printf("Error: Invalid mode '%s'. Valid modes are -r, -w, -rw, -wr.\n", flags);
        return;
    }

    // Check if file is already open
    if (is_file_opened(filename)) {
        printf("Error: File '%s' is already opened.\n", filename);
        return;
    }

    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = current_cluster;
    uint32_t first_data_sector = info->reserved_sectors + (info->fat_count * info->fat_size);

    // Traverse the directory clusters
    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + first_data_sector;
        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);
        int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);

        // Iterate over directory entries
        for (int i = 0; i < entry_count; i++) {
            uint8_t *entry_start = &sector_buffer[i * sizeof(FAT32_DirectoryEntry)];
            
            // Read name
            char name[12] = {0};
            memcpy(name, entry_start, 11);
            for (int j = 10; j >= 0 && name[j] == ' '; j--) {
                name[j] = '\0';
            }

            // Read attributes and cluster info
            uint8_t attributes = entry_start[11];
            uint16_t first_cluster_hi = entry_start[20] | (entry_start[21] << 8);
            uint16_t first_cluster_lo = entry_start[26] | (entry_start[27] << 8);
            uint32_t first_cluster = (first_cluster_hi << 16) | first_cluster_lo;

            // Check for a matching file name
            if (strcmp(name, filename) == 0 && !(attributes & ATTR_DIRECTORY)) {
                // Check maximum open files
                if (open_file_count >= MAX_OPEN_FILES) {
                    printf("Error: Maximum number of open files reached.\n");
                    return;
                }

                // Read file size
                uint32_t file_size = *(uint32_t *)(entry_start + 28);

                // Add to open files
                strncpy(open_files[open_file_count].name, name, 11);
                open_files[open_file_count].name[11] = '\0'; // Ensure null termination
                open_files[open_file_count].first_cluster = first_cluster;
                open_files[open_file_count].offset = 0;
                strncpy(open_files[open_file_count].mode, flags + 1, 2); // Skip the leading '-'
                open_files[open_file_count].mode[2] = '\0';
                open_files[open_file_count].size = file_size;

                printf("Opened '%s'\n", open_files[open_file_count].name);
                open_file_count++;
                return;
            }
        }
        cluster = get_next_cluster(image, info, cluster);
    }
    printf("Error: File '%s' does not exist.\n", filename);
}

void close_command(const char *filename) {

    // Search for the file in the open files array
    for (int i = 0; i < open_file_count; i++) {
        if (strcmp(open_files[i].name, filename) == 0) {
            // File found; remove it by shifting subsequent files down
            for (int j = i; j < open_file_count - 1; j++) {
                open_files[j] = open_files[j + 1];
            }

            open_file_count--; // Decrement the count of open files
            printf("File '%s' successfully closed.\n", filename);
            return;
        }
    }

    // If the file is not found in the open files array
    printf("Error: File '%s' is not open.\n", filename);
}

void lsof_command() {
    // Check if there are any open files
    if (open_file_count == 0) {
        printf("No files are currently opened.\n");
        return;
    }

    // Print header for the list of open files
    printf("Index | Name    | Mode  | Offset  | Path\n");

    // Iterate over the open files array and print details
    for (int i = 0; i < open_file_count; i++) {
        const OpenedFile *entry = &open_files[i];

        // Construct the full path by appending the file name to the current directory name
        char full_path[MAX_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "/fat32.img%s", current_dir_name);

        // Determine the mode based on the `mode` field
        const char *mode = entry->mode; // Since it's already in the correct format (e.g., "r", "w", "rw", "wr")

        // Print the file details
        printf("%-5d | %-7s | -%-4s | %-7u | %s\n", 
            i, 
            entry->name, 
            mode, 
            entry->offset, 
            full_path
        );
    }
}

void lseek_command(FILE *image, const FAT32_Info *info, const char *filename, uint32_t offset) {
    // Find the opened file entry corresponding to the given filename
    OpenedFile *file = NULL;
    for (int i = 0; i < open_file_count; i++) {
        if (strcmp(open_files[i].name, filename) == 0) {
            file = &open_files[i];
            break;
        }
    }
    // If the file is not found, print an error and return
    if (file == NULL) {
        printf("Error: File '%s' is not opened.\n", filename);
        return;
    }

    // Get the size of the file
    uint32_t file_size = get_file_size(image, info, file->first_cluster);

    // Check if the offset is within the bounds of the file size
    if (offset > file_size) {
        printf("Error: OFFSET is larger than the size of the file.\n");
        return;
    }

    // Update the offset of the file
    file->offset = offset;
}

void read_command(FILE *image, const FAT32_Info *info, const char *filename, uint32_t size_to_read) {
    // Locate the file in the open files array
    OpenedFile *file = NULL;
    for (int i = 0; i < open_file_count; i++) {
        if (strcmp(open_files[i].name, filename) == 0) {
            file = &open_files[i];
            break;
        }
    }

    if (file == NULL) {
        printf("Error: File '%s' does not exist or is not open.\n", filename);
        return;
    }

 
    if (strcmp(file->mode, "w") == 0 || strcmp(file->mode, "wr") == 0) {
        printf("Error: File '%s' is not opened for reading.\n", filename);
        return;
    }

    if (file->offset >= file->size) {
        printf("End of file reached for '%s'.\n", filename);
        return;
    }

    if (file->offset + size_to_read > file->size) {
        size_to_read = file->size - file->offset;  // Adjust to read up to EOF
    }

    uint32_t bytes_read = 0;
    uint32_t cluster = file->first_cluster;
    uint8_t sector_buffer[info->bytes_per_sector];

    // Traverse clusters and read data
    while (bytes_read < size_to_read && cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t cluster_start = (cluster - 2) * info->sectors_per_cluster + info->reserved_sectors + (info->fat_count * info->fat_size);

        for (uint32_t sector_idx = 0; sector_idx < info->sectors_per_cluster; sector_idx++) {
            fseek(image, (cluster_start + sector_idx) * info->bytes_per_sector, SEEK_SET);
            fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

            uint32_t offset_within_sector = file->offset % info->bytes_per_sector;
            uint32_t bytes_to_read = (size_to_read - bytes_read > info->bytes_per_sector - offset_within_sector) ? info->bytes_per_sector - offset_within_sector : size_to_read - bytes_read;

            for (uint32_t i = 0; i < bytes_to_read; i++) {
                putchar(sector_buffer[offset_within_sector + i]);
            }

            bytes_read += bytes_to_read;
            file->offset += bytes_to_read;
            offset_within_sector = 0;

            if (bytes_read >= size_to_read) {
                break;
            }
        }

        cluster = get_next_cluster(image, info, cluster);
    }

    printf("\nSuccessfully read %u bytes from '%s'.\n", bytes_read, filename);
}

void rm_command(FILE *image, const FAT32_Info *info, const char *target, int recursive) {
    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = current_cluster;
    uint32_t first_data_sector = info->reserved_sectors + (info->fat_count * info->fat_size);
    int target_found = 0;

    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + first_data_sector;

        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

        int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
        for (int i = 0; i < entry_count; i++) {
            FAT32_DirectoryEntry *entry = (FAT32_DirectoryEntry *)(sector_buffer + i * sizeof(FAT32_DirectoryEntry));
            char name[12] = {0};
            memcpy(name, entry->name, 11);
            for (int j = 10; j >= 0 && name[j] == ' '; j--) {
                name[j] = '\0';
            }

            // Skip empty or deleted entries
            if (name[0] == 0x00 || name[0] == 0xE5) continue;

            if (strcmp(name, target) == 0) {
                // Check if it's a directory
                if (entry->attributes & ATTR_DIRECTORY) {
                    if (!recursive) {
                        printf("Error: '%s' is a directory. Use rm -r to delete it recursively.\n", target);
                        return;
                    }

                    // Recursively delete contents of the directory
                    uint16_t first_cluster_hi = entry->first_cluster_hi;
                    uint16_t first_cluster_lo = entry->first_cluster_lo;
                    uint32_t dir_cluster = (first_cluster_hi << 16) | first_cluster_lo;
                    uint32_t sub_cluster = dir_cluster;

                    while (sub_cluster != 0x0FFFFFFF && sub_cluster != 0) {
                        // Load directory contents and call rm_command recursively
                        uint32_t sub_sector = (sub_cluster - 2) * info->sectors_per_cluster + first_data_sector;
                        uint8_t sub_sector_buffer[info->bytes_per_sector];
                        fseek(image, sub_sector * info->bytes_per_sector, SEEK_SET);
                        fread(sub_sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

                        int sub_entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
                        for (int k = 0; k < sub_entry_count; k++) {
                            FAT32_DirectoryEntry *sub_entry = (FAT32_DirectoryEntry *)(sub_sector_buffer + k * sizeof(FAT32_DirectoryEntry));
                            char sub_name[12] = {0};
                            memcpy(sub_name, sub_entry->name, 11);
                            for (int m = 10; m >= 0 && sub_name[m] == ' '; m--) {
                                sub_name[m] = '\0';
                            }

                            if (sub_name[0] != 0x00 && sub_name[0] != 0xE5 && strcmp(sub_name, ".") != 0 && strcmp(sub_name, "..") != 0) {
                                rm_command(image, info, sub_name, 1); // Recursive call
                            }
                        }

                        sub_cluster = get_next_cluster(image, info, sub_cluster);
                    }
                }

                // Free the clusters and mark the entry as deleted
                uint16_t first_cluster_hi = entry->first_cluster_hi;
                uint16_t first_cluster_lo = entry->first_cluster_lo;
                uint32_t current_cluster = (first_cluster_hi << 16) | first_cluster_lo;

                while (current_cluster != 0x0FFFFFFF && current_cluster != 0) {
                    uint32_t next_cluster = get_next_cluster(image, info, current_cluster);
                    allocate_cluster(image, info, current_cluster, 0); // Free the cluster
                    current_cluster = next_cluster;
                }

                memset(entry, 0, sizeof(FAT32_DirectoryEntry));
                entry->name[0] = 0xE5; // Mark the entry as deleted

                fseek(image, sector * info->bytes_per_sector, SEEK_SET);
                fwrite(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);
                target_found = 1;
                break;
            }
        }

        if (target_found) break;
        cluster = get_next_cluster(image, info, cluster);
    }

    if (!target_found) {
        printf("Error: File or directory '%s' not found.\n", target);
    }
}

void rmdir_command(FILE *image, const FAT32_Info *info, const char *dirname) {
    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = current_cluster;
    uint32_t first_data_sector = info->reserved_sectors + (info->fat_count * info->fat_size);
    int dir_found = 0;

    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + first_data_sector;

        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

        int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
        for (int i = 0; i < entry_count; i++) {
            FAT32_DirectoryEntry *entry = (FAT32_DirectoryEntry *)(sector_buffer + i * sizeof(FAT32_DirectoryEntry));
            char name[12] = {0};
            memcpy(name, entry->name, 11);
            for (int j = 10; j >= 0 && name[j] == ' '; j--) {
                name[j] = '\0';
            }

            if (strcmp(name, dirname) == 0) {
                if (!(entry->attributes & ATTR_DIRECTORY)) {
                    printf("Error: '%s' is not a directory.\n", dirname);
                    return;
                }

                uint16_t first_cluster_hi = entry->first_cluster_hi;
                uint16_t first_cluster_lo = entry->first_cluster_lo;
                uint32_t first_cluster = (first_cluster_hi << 16) | first_cluster_lo;

                uint8_t dir_sector_buffer[info->bytes_per_sector];
                uint32_t dir_cluster = first_cluster;
                int is_empty = 1;

                while (dir_cluster != 0x0FFFFFFF && dir_cluster != 0) {
                    uint32_t dir_sector = (dir_cluster - 2) * info->sectors_per_cluster + first_data_sector;
                    fseek(image, dir_sector * info->bytes_per_sector, SEEK_SET);
                    fread(dir_sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

                    int dir_entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
                    for (int j = 0; j < dir_entry_count; j++) {
                        FAT32_DirectoryEntry *dir_entry = (FAT32_DirectoryEntry *)(dir_sector_buffer + j * sizeof(FAT32_DirectoryEntry));
                        char dir_name[12] = {0};
                        memcpy(dir_name, dir_entry->name, 11);
                        for (int k = 10; k >= 0 && dir_name[k] == ' '; k--) {
                            dir_name[k] = '\0';
                        }

                        if (strcmp(dir_name, ".") != 0 && strcmp(dir_name, "..") != 0 &&
                            dir_name[0] != 0x00 && dir_name[0] != 0xE5) {
                            is_empty = 0;
                            printf("Directory is not empty. Found entry: '%s'\n", dir_name);
                            break;
                        }
                    }
                    if (!is_empty) break;
                    dir_cluster = get_next_cluster(image, info, dir_cluster);
                }

                if (!is_empty) {
                    printf("Error: Directory '%s' is not empty.\n", dirname);
                    return;
                }

                uint32_t current_cluster = first_cluster;
                while (current_cluster != 0x0FFFFFFF && current_cluster != 0) {
                    uint32_t next_cluster = get_next_cluster(image, info, current_cluster);
                    allocate_cluster(image, info, current_cluster, 0);
                    current_cluster = next_cluster;
                }

                memset(entry, 0, sizeof(FAT32_DirectoryEntry));
                entry->name[0] = 0xE5;

                fseek(image, sector * info->bytes_per_sector, SEEK_SET);
                fwrite(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

                printf("Directory '%s' removed successfully.\n", dirname);
                dir_found = 1;
                break;
            }
        }

        if (dir_found) break;
        cluster = get_next_cluster(image, info, cluster);
    }

    if (!dir_found) {
        printf("Error: Directory '%s' not found.\n", dirname);
    }
}

void write_command(FILE *image, const FAT32_Info *info, const char *filename, const char *string) {
    // Locate the file in the open files array
    OpenedFile *file = NULL;
    for (int i = 0; i < open_file_count; i++) {
        if (strcmp(open_files[i].name, filename) == 0) {
            file = &open_files[i];
            break;
        }
    }

    if (file == NULL) {
        printf("Error: File '%s' does not exist or is not open.\n", filename);
        return;
    }


    if (strcmp(file->mode, "r") == 0) {
        printf("Error: File '%s' is not opened for writing.\n", filename);
        return;
    }

    uint32_t string_length = strlen(string);
    uint32_t current_offset = file->offset;

    // Extend the file size if necessary
    if (current_offset + string_length > file->size) {
        uint32_t new_size = current_offset + string_length;
        while (file->size < new_size) {
            uint32_t next_cluster = find_free_cluster(image, info);
            if (next_cluster == 0x0FFFFFFF) {
                printf("Error: No free clusters available to extend the file.\n");
                return;
            }
            allocate_cluster(image, info, file->size, next_cluster);
            file->size += info->bytes_per_sector * info->sectors_per_cluster;
        }
        file->size = new_size;  // Update to reflect the new file size
    }

    // Write the string to the file starting at the current offset
    uint32_t bytes_written = 0;
    uint32_t cluster = file->first_cluster;
    uint8_t sector_buffer[info->bytes_per_sector];

    while (bytes_written < string_length && cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector_start = (cluster - 2) * info->sectors_per_cluster + info->reserved_sectors + (info->fat_count * info->fat_size);

        // Write data sector by sector
        for (uint32_t sector_idx = 0; sector_idx < info->sectors_per_cluster; sector_idx++) {
            fseek(image, (sector_start + sector_idx) * info->bytes_per_sector, SEEK_SET);
            fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

            uint32_t offset_within_sector = current_offset % info->bytes_per_sector;
            uint32_t bytes_left_in_sector = info->bytes_per_sector - offset_within_sector;
            uint32_t bytes_to_write = (string_length - bytes_written > bytes_left_in_sector) ? bytes_left_in_sector : string_length - bytes_written;

            memcpy(sector_buffer + offset_within_sector, string + bytes_written, bytes_to_write);

            fseek(image, (sector_start + sector_idx) * info->bytes_per_sector, SEEK_SET);
            fwrite(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

            current_offset += bytes_to_write;
            bytes_written += bytes_to_write;

            if (bytes_written >= string_length) {
                break;
            }
        }

        cluster = get_next_cluster(image, info, cluster);
    }

    file->offset += bytes_written;
    printf("Successfully written %u bytes to '%s'.\n", bytes_written, filename);
}

void rename_command(FILE *image, const FAT32_Info *info, const char *old_name, const char *new_name) {
    // Validate old_name and new_name are not "." or ".."
    if (strcmp(old_name, ".") == 0 || strcmp(old_name, "..") == 0) {
        printf("Error: Cannot rename special directories '.' or '..'.\n");
        return;
    }
    if (strcmp(new_name, ".") == 0 || strcmp(new_name, "..") == 0) {
        printf("Error: Invalid new name '%s'.\n", new_name);
        return;
    }

    // Check if the old_name exists
    uint8_t sector_buffer[info->bytes_per_sector];
    uint32_t cluster = current_cluster;
    uint32_t first_data_sector = info->reserved_sectors + (info->fat_count * info->fat_size);
    FAT32_DirectoryEntry *entry_to_rename = NULL;

    while (cluster != 0x0FFFFFFF && cluster != 0) {
        uint32_t sector = (cluster - 2) * info->sectors_per_cluster + first_data_sector;

        fseek(image, sector * info->bytes_per_sector, SEEK_SET);
        fread(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

        int entry_count = info->bytes_per_sector / sizeof(FAT32_DirectoryEntry);
        for (int i = 0; i < entry_count; i++) {
            FAT32_DirectoryEntry *entry = (FAT32_DirectoryEntry *)&sector_buffer[i * sizeof(FAT32_DirectoryEntry)];
            char name[12] = {0};
            memcpy(name, entry->name, 11);
            for (int j = 10; j >= 0 && name[j] == ' '; j--) {
                name[j] = '\0';
            }

            // Check for the old_name
            if (strcmp(name, old_name) == 0) {
                // Check if the file is open
                if (is_file_opened(old_name)) {
                    printf("Error: File '%s' is currently open and cannot be renamed.\n", old_name);
                    return;
                }

                entry_to_rename = entry;
                break;
            }

            // Check for the new_name
            if (strcmp(name, new_name) == 0) {
                printf("Error: File or directory with name '%s' already exists.\n", new_name);
                return;
            }
        }

        if (entry_to_rename) break;
        cluster = get_next_cluster(image, info, cluster);
    }

    if (!entry_to_rename) {
        printf("Error: File or directory '%s' does not exist.\n", old_name);
        return;
    }

    // Update the name of the entry
    char padded_new_name[11] = {0};
    strncpy(padded_new_name, new_name, 11);
    for (int i = strlen(new_name); i < 11; i++) {
        padded_new_name[i] = ' '; // Pad with spaces
    }
    memcpy(entry_to_rename->name, padded_new_name, 11);

    // Write the updated sector back to the image
    fseek(image, -info->bytes_per_sector, SEEK_CUR); // Rewind to the start of the sector
    fwrite(sector_buffer, sizeof(uint8_t), info->bytes_per_sector, image);

    printf("Renamed '%s' to '%s'.\n", old_name, new_name);
}

void dump_command(FILE *image, const FAT32_Info *info, const char *filename) {
    OpenedFile *file = NULL;

    // Check if the file is open
    for (int i = 0; i < open_file_count; i++) {
        if (strcmp(open_files[i].name, filename) == 0) {
            file = &open_files[i];
            break;
        }
    }

    if (file == NULL) {
        printf("Error: File or directory '%s' not found.\n", filename);
        return;
    }

    // Read file metadata from the OpenedFile structure
    uint32_t cluster = file->first_cluster;
    uint32_t file_size = file->size;
    uint32_t cluster_size = info->bytes_per_sector * info->sectors_per_cluster;
    uint8_t cluster_buffer[cluster_size];
    uint32_t bytes_dumped = 0;

    printf("Dumping file '%s'...\n", filename);

    // Traverse clusters and dump their contents
    while (cluster != 0x0FFFFFFF && cluster != 0 && bytes_dumped < file_size) {
        uint32_t cluster_start_sector = (cluster - 2) * info->sectors_per_cluster +
                                        info->reserved_sectors + (info->fat_count * info->fat_size);
        fseek(image, cluster_start_sector * info->bytes_per_sector, SEEK_SET);
        fread(cluster_buffer, sizeof(uint8_t), cluster_size, image);

        for (uint32_t i = 0; i < cluster_size && bytes_dumped < file_size; i++) {
            if (i % 16 == 0) {
                printf("\n%08X  ", bytes_dumped);
            }
            printf("%02X ", cluster_buffer[i]);
            bytes_dumped++;
        }

        cluster = get_next_cluster(image, info, cluster);
    }

    printf("\nTotal bytes dumped: %u\n", bytes_dumped);
}


void handle_exit() {
    if (image) fclose(image);
    printf("Exiting...\n");
    exit(0);
}

void shell_prompt(const char *image_name) {
    if (strcmp(current_dir_name, "") == 0) {
        // If current directory is empty, display just the image name.
        printf("./%s/> ", image_name);
    } else {
        // Display the full path starting with './fat32.img/' followed by the current directory name.
        printf("./%s%s/> ", image_name, current_dir_name);
    }
}

int main(int argc, char *argv[]) {
    image = fopen(argv[1], "rb+");
    char *image_name = basename(argv[1]);  
    char command[256];
    FAT32_Info info = parse_boot_sector(image);
    current_cluster = info.root_cluster; //root cluster
   
    if (argc != 2) {
        fprintf(stderr, "Usage: ./filesys [FAT32 ISO]\n");
        return EXIT_FAILURE;
    }
    if (!image) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    while (1) {
        shell_prompt(image_name); 
        if (!fgets(command, sizeof(command), stdin)) break;

        command[strcspn(command, "\n")] = '\0';  // Remove newline character

        // Process commands with arguments
        if (strcmp(command, "info") == 0) {
            print_info(&info);
        } 
        else if (strcmp(command, "ls") == 0) {
            ls_command(image, &info);
        } 
        else if (strncmp(command, "cd ", 3) == 0) {
            char dirname[MAX_PATH_LENGTH];
            parse_quoted_argument(command + 3, dirname);  // Skip the "cd " part and get the argument
            if (strlen(dirname) > 0) {
                cd_command(image, &info, dirname);
            } else {
                printf("Error: Invalid directory name.\n");
            }
        } 
        else if (strncmp(command, "mkdir ", 6) == 0) {
            char dirname[MAX_PATH_LENGTH];
            parse_quoted_argument(command + 6, dirname);  // Skip the "mkdir " part and get the argument
            if (strlen(dirname) > 0) {
                mkdir_command(image, &info, dirname);
            } else {
                printf("Error: Invalid directory name.\n");
            }
        }
        else if (strcmp(command, "exit") == 0) {
            handle_exit();
        } 
        else if (strncmp(command, "creat ", 6)== 0)
        {
        	char newfile[MAX_PATH_LENGTH];
        	parse_quoted_argument(command + 6, newfile);
            if (strlen(newfile) > 0) {
                creat_command(image, &info, newfile);
            } else {
                printf("Error: Invalid directory name.\n");
            }
        }
        else if (strncmp(command, "open ", 5) == 0) {
    		char args[MAX_PATH_LENGTH];
    		parse_quoted_argument(command + 5, args); // Skip "open " part

    		char *filename = strtok(args, " ");
    		char *flags = strtok(NULL, " ");

            if (filename && flags) {
                open_command(image, &info, filename, flags);
            } else {
        		printf("Error: Invalid arguments for 'open'. Usage: open [FILENAME] [FLAGS].\n");
    		}
        }
        else if (strncmp(command, "close ", 6) == 0) {
            char filename[MAX_PATH_LENGTH];
            parse_quoted_argument(command + 6, filename); // Skip "close " part

            if (strlen(filename) > 0) {
            close_command(filename);
            } 
            else {
                printf("Error: Invalid arguments for 'close'. Usage: close [FILENAME].\n");
            }
        }
        else if (strncmp(command,"lsof", 4) ==0)
        {
            lsof_command();
        
        }
        else if (strncmp(command, "lseek ", 6) == 0) {
            char filename[MAX_PATH_LENGTH];
            uint32_t offset;

            // First, try parsing filename and offset using sscanf
            int n = sscanf(command + 6, "\"%[^\"]\" %u", filename, &offset); // With quotes
            if (n != 2) {
                // If sscanf didn't work, try without quotes
                n = sscanf(command + 6, "%s %u", filename, &offset);
            }
            if (n == 2) {
                // If filename and offset are both extracted
                lseek_command(image, &info, filename, offset);
            } else {
                printf("Error: Invalid OFFSET. Usage: lseek [FILENAME] [OFFSET].\n");
            }
        }
        else if (strncmp(command, "read ", 5) == 0) {
            char filename[MAX_PATH_LENGTH];
            uint32_t size;
            
            if (sscanf(command, "read %11s %u", filename, &size) != 2) {
                printf("Error: Invalid syntax. Usage: read <filename> <num_bytes>\n");
                continue;
            }

            read_command(image, &info, filename, size);
        }
        else if (strncmp(command, "rm ", 3) == 0) {
    char target[MAX_PATH_LENGTH];
    int recursive = 0;

    if (strncmp(command + 3, "-r ", 3) == 0) {
        recursive = 1;
        sscanf(command + 6, "%s", target); // Skip "rm -r "
    } else {
        sscanf(command + 3, "%s", target); // Skip "rm "
    }

    if (strlen(target) > 0) {
        rm_command(image, &info, target, recursive);
    } else {
        printf("Error: Invalid command. Usage: rm [-r] [FILENAME|DIRECTORY].\n");
    }
}

        else if (strncmp(command, "rmdir ", 6) == 0) {
            char dirname[MAX_PATH_LENGTH];
            parse_quoted_argument(command + 6, dirname);
            if (strlen(dirname) > 0) {
                rmdir_command(image, &info, dirname); // Remove directory
            } else {
                printf("Error: Invalid directory name.\n");
            }
        } 
        else if (strncmp(command, "write ", 6) == 0) {
            char filename[MAX_PATH_LENGTH];
            char string[MAX_PATH_LENGTH];

            // Try parsing the command with the filename being unquoted and the string being quoted
            int n = sscanf(command + 6, "%s \"%[^\"]\"", filename, string); // Mixture: unquoted filename, quoted string

            if (n == 2) {
                write_command(image, &info, filename, string); // Call the write command function
            } else {
                printf("Error: Invalid syntax. Usage: write [FILENAME] [STRING].\n");
            }
        }
        else if (strncmp(command, "rename ", 7) == 0) {
            char args[MAX_PATH_LENGTH];
            parse_quoted_argument(command + 7, args);

            char *old_name = strtok(args, " ");
            char *new_name = strtok(NULL, " ");

            if (old_name && new_name) {
                rename_command(image, &info, old_name, new_name);
            } else {
                printf("Error: Invalid arguments for 'rename'. Usage: rename [FILENAME] [NEW_FILENAME].\n");
            }
        }
        else if (strncmp(command, "dump ", 5) == 0) {
            char filename[MAX_PATH_LENGTH];
            parse_quoted_argument(command + 5, filename); // Extract the filename
            if (strlen(filename) > 0) {
                dump_command(image, &info, filename);
            } else {
                printf("Error: Invalid filename.\n");
            }
        }

        else {
            printf("Unrecognized command: %s\n", command);
        }
    }
    return EXIT_SUCCESS;
}






