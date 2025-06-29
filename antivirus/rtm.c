#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (8192 * (EVENT_SIZE + 16))  // Increased buffer size
#define PATH_SEPARATOR '/'
#define MAX_WATCHES 1000

// Define log levels
#define LOG_INFO 1
#define LOG_WARNING 2
#define LOG_ERROR 3
#define LOG_RESULT 4  // Special level for results that should go to GUI

// Hash table for tracking recently processed files to avoid duplicates
#define HASH_SIZE 1024
// Update FileCacheEntry to include inode and mtime
typedef struct FileCacheEntry {
    char path[PATH_MAX];
    ino_t inode;
    time_t mtime;
    time_t timestamp;
    struct FileCacheEntry *next;
} FileCacheEntry;

FileCacheEntry *file_cache[HASH_SIZE] = {NULL};
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// Track recently created files to avoid duplicate events
typedef struct RecentFileEntry {
    char path[PATH_MAX];
    time_t timestamp;
    struct RecentFileEntry *next;
} RecentFileEntry;

#define RECENT_SIZE 256
RecentFileEntry *recent_files[RECENT_SIZE] = {NULL};
pthread_mutex_t recent_mutex = PTHREAD_MUTEX_INITIALIZER;

// Volatile flag to signal threads to exit
volatile int running = 1;

// Signal handler to gracefully exit monitoring
void handle_signal(int sig) {
    running = 0;
}

// Hash function for file paths
unsigned int hash_path(const char *path) {
    unsigned int hash = 0;
    while (*path) {
        hash = hash * 31 + (*path++);
    }
    return hash % HASH_SIZE;
}

// Check if a file was recently created (within last 5 seconds)
int was_recently_created(const char *path) {
    unsigned int hash = hash_path(path) % RECENT_SIZE;
    time_t now = time(NULL);
    
    pthread_mutex_lock(&recent_mutex);
    
    RecentFileEntry *entry = recent_files[hash];
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            // If created within 5 seconds, it's recent
            if (now - entry->timestamp < 5) {
                pthread_mutex_unlock(&recent_mutex);
                return 1;
            }
            // Update entry with current time
            entry->timestamp = now;
            pthread_mutex_unlock(&recent_mutex);
            return 0;
        }
        entry = entry->next;
    }
    
    // Not found, add to recent files
    RecentFileEntry *new_entry = malloc(sizeof(RecentFileEntry));
    if (new_entry) {
        strncpy(new_entry->path, path, PATH_MAX-1);
        new_entry->path[PATH_MAX-1] = '\0';
        new_entry->timestamp = now;
        new_entry->next = recent_files[hash];
        recent_files[hash] = new_entry;
    }
    
    pthread_mutex_unlock(&recent_mutex);
    return 0;
}

// Mark a file as recently created
void mark_file_created(const char *path) {
    unsigned int hash = hash_path(path) % RECENT_SIZE;
    time_t now = time(NULL);
    
    pthread_mutex_lock(&recent_mutex);
    
    // Check if it already exists
    RecentFileEntry *entry = recent_files[hash];
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            // Update timestamp
            entry->timestamp = now;
            pthread_mutex_unlock(&recent_mutex);
            return;
        }
        entry = entry->next;
    }
    
    // Not found, add to recent files
    RecentFileEntry *new_entry = malloc(sizeof(RecentFileEntry));
    if (new_entry) {
        strncpy(new_entry->path, path, PATH_MAX-1);
        new_entry->path[PATH_MAX-1] = '\0';
        new_entry->timestamp = now;
        new_entry->next = recent_files[hash];
        recent_files[hash] = new_entry;
    }
    
    pthread_mutex_unlock(&recent_mutex);
}

// Clean up the recent files list
void cleanup_recent_files() {
    time_t now = time(NULL);
    
    pthread_mutex_lock(&recent_mutex);
    
    for (int i = 0; i < RECENT_SIZE; i++) {
        RecentFileEntry **pp = &recent_files[i];
        RecentFileEntry *entry;
        
        while (*pp) {
            entry = *pp;
            if (now - entry->timestamp > 60) { // Remove entries older than 60 seconds
                *pp = entry->next;
                free(entry);
            } else {
                pp = &entry->next;
            }
        }
    }
    
    pthread_mutex_unlock(&recent_mutex);
}

// Free all recent file entries
void free_recent_files() {
    pthread_mutex_lock(&recent_mutex);
    
    for (int i = 0; i < RECENT_SIZE; i++) {
        RecentFileEntry *entry = recent_files[i];
        while (entry) {
            RecentFileEntry *next = entry->next;
            free(entry);
            entry = next;
        }
        recent_files[i] = NULL;
    }
    
    pthread_mutex_unlock(&recent_mutex);
}

// ...existing code...


// Update was_recently_processed to check inode and mtime
int was_recently_processed(const char *path) {
   
    return 0;
}

// ...existing code...

// Clean up cache entries older than 60 seconds
void cleanup_cache() {
    time_t now = time(NULL);
    
    pthread_mutex_lock(&cache_mutex);
    
    for (int i = 0; i < HASH_SIZE; i++) {
        FileCacheEntry **pp = &file_cache[i];
        FileCacheEntry *entry;
        
        while (*pp) {
            entry = *pp;
            if (now - entry->timestamp > 60) {
                *pp = entry->next;
                free(entry);
            } else {
                pp = &entry->next;
            }
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
}

// Free all cache entries
void free_cache() {
    pthread_mutex_lock(&cache_mutex);
    
    for (int i = 0; i < HASH_SIZE; i++) {
        FileCacheEntry *entry = file_cache[i];
        while (entry) {
            FileCacheEntry *next = entry->next;
            free(entry);
            entry = next;
        }
        file_cache[i] = NULL;
    }
    
    pthread_mutex_unlock(&cache_mutex);
}

void log_message(int level, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    if (level == LOG_RESULT) {
        // GUI-bound messages always start with [R]
        fprintf(stdout, "[R] ");
        vfprintf(stdout, format, args);
        fprintf(stdout, "\n");
    } else {
        // Regular terminal messages
        const char* prefix;
        switch(level) {
            case LOG_ERROR:
                prefix = "[-] ";
                break;
            case LOG_WARNING:
                prefix = "[!] ";
                break;
            default:
                prefix = "[+] ";
        }
        fprintf(stderr, "%s", prefix);
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
    }
    
    if (level == LOG_RESULT) {
        fflush(stdout); // Make sure GUI messages go out immediately
    } else {
        fflush(stderr);
    }
    
    va_end(args);
}

void CallDetectionEngine(const char* filePath) {
    // Skip if this file was just processed
    if (was_recently_processed(filePath)) {
        log_message(LOG_INFO, "Skipping recently scanned file: %s", filePath);
        return;
    }

    // Check if file still exists before scanning
    struct stat st;
    if (stat(filePath, &st) != 0) {
        log_message(LOG_INFO, "File no longer exists, skipping scan: %s", filePath);
        return;
    }
    
    // Skip if file size is 0
    if (st.st_size == 0) {
        log_message(LOG_INFO, "Skipping empty file: %s", filePath);
        return;
    }
    
    log_message(LOG_INFO, "Scanning file: %s", filePath);
    log_message(LOG_RESULT, "FILE_SCANNING:%s", filePath);

    // Construct the command to execute
    char command[1024];
    snprintf(command, sizeof(command), "./engine \"%s\"", filePath);
    
    // Use popen to capture output
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        log_message(LOG_ERROR, "Failed to execute command: %s", command);
        return;
    }
    
    // Read and forward the output
    char output[1024];
    int threats_found = 0;
    
    while (fgets(output, sizeof(output), fp) != NULL) {
        // Remove newline characters
        size_t len = strlen(output);
        if (len > 0 && output[len-1] == '\n') {
            output[len-1] = '\0';
        }
        
        // Check for [R] prefix which indicates GUI messages
        if (strncmp(output, "[R]", 3) == 0) {
            // Forward GUI messages directly to stdout for the Python process to capture
            printf("%s\n", output);
            fflush(stdout);
            
            // Count detections for summary
            if (strstr(output, "DETECTION:") || strstr(output, "UNSAFE:")) {
                threats_found++;
            }
        }
    }
    
    // Close the pipe
    int returnCode = pclose(fp);
    
    // Report scan completion to GUI
    if (returnCode != 0) {
        log_message(LOG_ERROR, "Scan failed with error code: %d for file: %s", returnCode, filePath);
    } else {
        // Only log success to terminal, not to GUI
        log_message(LOG_INFO, "Scan completed for: %s", filePath);
        
        // If no threats were found, explicitly mark as safe for GUI
        if (threats_found == 0) {
            log_message(LOG_RESULT, "SAFE:%s", filePath);
        }
    }
}

// Function to perform initial scan of a directory
void scanDirectoryRecursively(const char* dirPath) {
    DIR* dir;
    struct dirent* entry;
    struct stat path_stat;
    char fullPath[PATH_MAX];

    log_message(LOG_INFO, "Scanning directory: %s", dirPath);

    if (!(dir = opendir(dirPath))) {
        log_message(LOG_ERROR, "Error opening directory for scan: %s - %s", dirPath, strerror(errno));
        return;
    }

    while ((entry = readdir(dir)) != NULL && running) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_name[0] == '.') {
            continue; // Skip . and .. and hidden files
        }

        snprintf(fullPath, PATH_MAX, "%s%c%s", dirPath, PATH_SEPARATOR, entry->d_name);
        
        if (stat(fullPath, &path_stat) == 0) {
            if (S_ISDIR(path_stat.st_mode)) {
                // Recursively scan subdirectories
                scanDirectoryRecursively(fullPath);
            } 
            else if (S_ISREG(path_stat.st_mode)) {
                // Scan regular files
                CallDetectionEngine(fullPath);
            }
        }
    }
    
    closedir(dir);
}

// Data structure for watch information
typedef struct {
    int wd;             // Watch descriptor
    char *path;         // Path being watched
} WatchInfo;

// Function to monitor a directory (thread entry point)
void* monitorDirectory(void* arg) {
    char* rootDir = (char*)arg;
    int fd;
    char buffer[EVENT_BUF_LEN];
    WatchInfo watches[MAX_WATCHES];
    int watch_count = 0;
    
    // Set up signal handler in this thread
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // First, perform an initial scan
    log_message(LOG_INFO, "Starting initial scan of: %s", rootDir);
    log_message(LOG_RESULT, "SCAN_START:%s", rootDir);
    scanDirectoryRecursively(rootDir);
    log_message(LOG_INFO, "Initial scan completed for: %s", rootDir);
    log_message(LOG_RESULT, "SCAN_COMPLETE:%s", rootDir);
    
    // Initialize inotify
    fd = inotify_init();
    if (fd < 0) {
        log_message(LOG_ERROR, "Failed to initialize inotify: %s", strerror(errno));
        free(rootDir);
        return NULL;
    }
    
    // Add watch for the root directory
    int wd = inotify_add_watch(fd, rootDir, 
        IN_CREATE | IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
    
    if (wd < 0) {
        log_message(LOG_ERROR, "Failed to add watch for %s: %s", rootDir, strerror(errno));
        close(fd);
        free(rootDir);
        return NULL;
    }
    
    // Store the watch info
    watches[watch_count].wd = wd;
    watches[watch_count].path = strdup(rootDir);
    watch_count++;
    
    log_message(LOG_INFO, "Real-time monitoring active for: %s", rootDir);
    log_message(LOG_RESULT, "MONITORING_ACTIVE:%s", rootDir);
    
    // Set up recursive watches for subdirectories
    DIR* dir = opendir(rootDir);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL && watch_count < MAX_WATCHES) {
            if (entry->d_name[0] == '.' || strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue; // Skip hidden directories and . and ..
            }
            
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "%s/%s", rootDir, entry->d_name);
            
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                // It's a directory, add a watch
                int wd = inotify_add_watch(fd, path, 
                    IN_CREATE | IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
                
                if (wd >= 0) {
                    watches[watch_count].wd = wd;
                    watches[watch_count].path = strdup(path);
                    watch_count++;
                    log_message(LOG_INFO, "Added watch for subdirectory: %s", path);
                }
            }
        }
        closedir(dir);
    }
    
    // Main monitoring loop
    time_t last_cleanup = time(NULL);
    
    while (running) {
        // Periodic cleanup
        time_t now = time(NULL);
        if (now - last_cleanup > 60) {
            cleanup_cache();
            cleanup_recent_files();
            last_cleanup = now;
        }
        
        // Set up select with timeout
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout
        timeout.tv_usec = 0;
        
        int ret = select(fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (ret < 0) {
            if (errno == EINTR) continue; // Interrupted system call
            log_message(LOG_ERROR, "Select error: %s", strerror(errno));
            break;
        }
        
        if (ret == 0) continue; // Timeout - just loop
        
        if (!FD_ISSET(fd, &read_fds)) continue; // Not our fd
        
        // Read events
        int length = read(fd, buffer, EVENT_BUF_LEN);
        
        if (length < 0) {
            if (errno == EINTR) continue; // Interrupted system call
            log_message(LOG_ERROR, "Error reading from inotify fd: %s", strerror(errno));
            break;
        }
        
        // Process events
        int i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];
            
            // Skip events with no name
            if (event->len == 0) {
                i += EVENT_SIZE;
                continue;
            }
            
            // Skip hidden files
            if (event->name[0] == '.') {
                i += EVENT_SIZE + event->len;
                continue;
            }
            
            // Find the path for this watch
            char* watch_path = NULL;
            for (int j = 0; j < watch_count; j++) {
                if (watches[j].wd == event->wd) {
                    watch_path = watches[j].path;
                    break;
                }
            }
            
            if (watch_path == NULL) {
                // Unknown watch descriptor
                i += EVENT_SIZE + event->len;
                continue;
            }
            
            // Construct the full path
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "%s/%s", watch_path, event->name);
            
            // Handle events for directories
            if (event->mask & IN_ISDIR) {
                if (event->mask & IN_CREATE) {
                    log_message(LOG_INFO, "Directory created: %s", path);
                    log_message(LOG_RESULT, "DIR_CREATED:%s", path);
                    
                    // Add a watch for the new directory if we have room
                    if (watch_count < MAX_WATCHES) {
                        int wd = inotify_add_watch(fd, path, 
                            IN_CREATE | IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
                        
                        if (wd >= 0) {
                            watches[watch_count].wd = wd;
                            watches[watch_count].path = strdup(path);
                            watch_count++;
                            log_message(LOG_INFO, "Added watch for new directory: %s", path);
                        }
                    }
                }
                else if (event->mask & IN_DELETE) {
                    log_message(LOG_INFO, "Directory deleted: %s", path);
                    log_message(LOG_RESULT, "DIR_DELETED:%s", path);
                }
            }
            // Handle events for files
            else {
                // First determine the correct action
                int should_scan = 0;
                
                if (event->mask & IN_CREATE) {
                    log_message(LOG_INFO, "File created: %s", path);
                    log_message(LOG_RESULT, "FILE_CREATED:%s", path);
                    
                    // Mark this file as recently created
                    mark_file_created(path);
                    
                    // Wait a moment for the file to be completely written
                    usleep(200000);  // 200ms
                    should_scan = 1;
                }
                else if (event->mask & IN_CLOSE_WRITE) {
                    // Only report as a modification if it wasn't recently created
                    if (!was_recently_created(path)) {
                        log_message(LOG_INFO, "File modified: %s", path);
                        log_message(LOG_RESULT, "FILE_MODIFIED:%s", path);
                        should_scan = 1;
                    } else {
                        log_message(LOG_INFO, "Skipping redundant close-write after recent creation: %s", path);
                    }
                }
                else if (event->mask & IN_DELETE) {
                    log_message(LOG_INFO, "File deleted: %s", path);
                    log_message(LOG_RESULT, "FILE_DELETED:%s", path);
                }
                else if (event->mask & IN_MOVED_TO) {
                    log_message(LOG_INFO, "File moved to: %s", path);
                    log_message(LOG_RESULT, "FILE_MOVED_TO:%s", path);
                    should_scan = 1;
                }
                else if (event->mask & IN_MOVED_FROM) {
                    log_message(LOG_INFO, "File moved from: %s", path);
                    log_message(LOG_RESULT, "FILE_MOVED_FROM:%s", path);
                }
                
                // Scan the file if needed
                if (should_scan) {
                    // Double check file exists and is readable
                    struct stat st;
                    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                        CallDetectionEngine(path);
                    } else {
                        log_message(LOG_INFO, "Skipping scan - file doesn't exist or isn't regular: %s", path);
                    }
                }
            }
            
            i += EVENT_SIZE + event->len;
        }
    }
    
    // Clean up watches
    for (int i = 0; i < watch_count; i++) {
        inotify_rm_watch(fd, watches[i].wd);
        free(watches[i].path);
    }
    
    close(fd);
    free(rootDir);
    
    log_message(LOG_INFO, "Monitoring stopped");
    log_message(LOG_RESULT, "MONITORING_STOPPED");
    
    return NULL;
}

int main(int argc, char* argv[]) {
    // Set up signal handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Initialize the mutexes
    pthread_mutex_init(&cache_mutex, NULL);
    pthread_mutex_init(&recent_mutex, NULL);
    
    // Get the directories to monitor
    char pathList[PATH_MAX];
    
    if (argc > 1) {
        strncpy(pathList, argv[1], PATH_MAX - 1);
        pathList[PATH_MAX - 1] = '\0';
    } else {
        // Default path
        log_message(LOG_INFO, "No path specified, using default path /tmp");
        strcpy(pathList, "/tmp");
    }
    
    log_message(LOG_INFO, "Starting real-time monitoring with paths: %s", pathList);
    log_message(LOG_RESULT, "RTM_START:%s", pathList);
    
    // Parse the path list and create a thread for each directory
    char* token = strtok(pathList, ";");
    pthread_t threads[100];  // Maximum 100 threads
    int thread_count = 0;
    
    while (token != NULL && thread_count < 100) {
        // Skip empty tokens
        if (strlen(token) == 0) {
            token = strtok(NULL, ";");
            continue;
        }
        
        log_message(LOG_INFO, "Starting monitoring for directory: %s", token);
        
        // Copy the token because strtok modifies it
        char* dir_path = strdup(token);
        if (!dir_path) {
            log_message(LOG_ERROR, "Failed to allocate memory for directory path");
            continue;
        }
        
        // Create a thread to monitor this directory
        if (pthread_create(&threads[thread_count], NULL, monitorDirectory, dir_path) != 0) {
            log_message(LOG_ERROR, "Failed to create monitoring thread for %s: %s", 
                        dir_path, strerror(errno));
            free(dir_path);
        } else {
            thread_count++;
        }
        
        token = strtok(NULL, ";");
    }
    
    if (thread_count == 0) {
        log_message(LOG_ERROR, "No valid directories to monitor");
        pthread_mutex_destroy(&cache_mutex);
        pthread_mutex_destroy(&recent_mutex);
        return 1;
    }
    
    log_message(LOG_INFO, "Monitoring %d directories. Press 'q' then ENTER to quit", thread_count);
    
    // Wait for 'q' to exit
    char c;
    do {
        c = getchar();
    } while (c != 'q' && running);
    
    // Signal threads to exit
    running = 0;
    
    // Wait for all threads to finish
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Clean up resources
    free_cache();
    free_recent_files();
    pthread_mutex_destroy(&cache_mutex);
    pthread_mutex_destroy(&recent_mutex);
    
    log_message(LOG_INFO, "Real-time monitoring terminated");
    
    return 0;
}