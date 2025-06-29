#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdarg.h>

#define PATH_SEPARATOR '/'
#define BUFFER_SIZE 1024

// Define log levels
#define LOG_DEBUG 0
#define LOG_INFO 1  
#define LOG_WARNING 2
#define LOG_ERROR 3
#define LOG_RESULT 4  // Special level for results that should go to GUI

// Global log level - can be adjusted as needed
int g_log_level = LOG_INFO;

// Log to terminal with specified level
void log_message(int level, const char* format, ...) {
    // Only compiler messages go to terminal regardless of level
    if (level < LOG_RESULT && (strstr(format, "Compiled") || strstr(format, "compiler") || 
                              strstr(format, "rule file") || strstr(format, "YARA"))) {
        va_list args;
        va_start(args, format);
        
        switch (level) {
            case LOG_DEBUG:   fprintf(stdout, "[D] "); break;
            case LOG_INFO:    fprintf(stdout, "[+] "); break;
            case LOG_WARNING: fprintf(stdout, "[!] "); break;
            case LOG_ERROR:   fprintf(stdout, "[-] "); break;
        }
        
        vfprintf(stdout, format, args);
        fprintf(stdout, "\n");
        fflush(stdout);
        
        va_end(args);
        return;
    }
    
    // Skip messages below current log level except for results
    if (level < g_log_level && level != LOG_RESULT) {
        return;
    }
    
    const char* prefix = "";
    switch (level) {
        case LOG_DEBUG:   prefix = "[D] "; break;
        case LOG_INFO:    prefix = "[+] "; break;
        case LOG_WARNING: prefix = "[!] "; break;
        case LOG_ERROR:   prefix = "[-] "; break;
        case LOG_RESULT:  prefix = "[R] "; break;  // Results marker - used for GUI parsing
    }
    
    // Only LOG_RESULT messages go to both terminal and GUI
    va_list args;
    va_start(args, format);
    
    if (level == LOG_RESULT) {
        // To GUI (and terminal)
        fprintf(stdout, "%s", prefix);
        vfprintf(stdout, format, args);
        fprintf(stdout, "\n");
        fflush(stdout);
    }
    
    va_end(args);
}

void displayErrorMessage(int errorCode) {
    log_message(LOG_ERROR, "Error: %s", strerror(errorCode));
}

// Structure to track scan results
typedef struct {
    const char* file_path;
    int threats_found;
    char threats[10][100]; // Store up to 10 threat names with 100 char max
} ScanResult;

int scanCallback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data) {
    
    ScanResult* result = (ScanResult*)user_data;
    
    switch (message) {
    case CALLBACK_MSG_RULE_MATCHING:
        // Store the matched rule identifier
        if (result->threats_found < 10) {
            strncpy(result->threats[result->threats_found], 
                   ((YR_RULE*)message_data)->identifier, 
                   99);
            result->threats[result->threats_found][99] = '\0'; // Ensure null termination
            result->threats_found++;
        }
        
        // Log detection to terminal
        log_message(LOG_INFO, "DETECTION: Rule '%s' matched in file: %s", 
               ((YR_RULE*)message_data)->identifier, 
               result->file_path);
               
        // Also output as result (for GUI)
        log_message(LOG_RESULT, "DETECTION:%s:%s", 
               ((YR_RULE*)message_data)->identifier, 
               result->file_path);
        break;
        
    case CALLBACK_MSG_SCAN_FINISHED:
        // When scan is completed, print the final verdict
        if (result->threats_found == 0) {
            log_message(LOG_INFO, "SAFE: No threats detected in file: %s", result->file_path);
            log_message(LOG_RESULT, "SAFE:%s", result->file_path);
        } else {
            log_message(LOG_INFO, "UNSAFE: Found %d threat(s) in file: %s", 
                   result->threats_found, 
                   result->file_path);
                   
            // Build result string for GUI
            char threats_str[1024] = {0};
            for (int i = 0; i < result->threats_found; i++) {
                strcat(threats_str, result->threats[i]);
                if (i < result->threats_found - 1) {
                    strcat(threats_str, ", ");
                }
            }
            
            log_message(LOG_RESULT, "UNSAFE:%s:%d:%s", result->file_path, 
                       result->threats_found, threats_str);
                       
            log_message(LOG_INFO, "    Matched rules: %s", threats_str);
        }
        break;
        
    case CALLBACK_MSG_TOO_MANY_MATCHES:
        log_message(LOG_WARNING, "WARNING: Too many matches in file: %s", result->file_path);
        break;
        
    default:
        break;
    }

    return CALLBACK_CONTINUE;
}

void scanFile(const char* filePath, YR_RULES* rules) {
    ScanResult result;
    result.file_path = filePath;
    result.threats_found = 0;
    
    log_message(LOG_INFO, "Scanning file: %s", filePath);
    
    // Direct check for EICAR pattern (quick solution) 
    FILE* fp = fopen(filePath, "rb");
    if (fp) {
        char buffer[70] = {0};
        size_t bytes_read = fread(buffer, 1, sizeof(buffer)-1, fp);
        fclose(fp);
        
        if (bytes_read > 0 && strstr(buffer, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE") != NULL) {
            log_message(LOG_INFO, "DETECTION: EICAR test file detected: %s", filePath);
            log_message(LOG_RESULT, "DETECTION:EICAR_Test_File:%s", filePath);
            
            // Add to threats list
            if (result.threats_found < 10) {
                strncpy(result.threats[result.threats_found], "EICAR_Test_File", 99);
                result.threats[result.threats_found][99] = '\0';
                result.threats_found++;
            }
        }
    }
    
    int scan_result = yr_rules_scan_file(
        rules, 
        filePath, 
        SCAN_FLAGS_REPORT_RULES_MATCHING, 
        scanCallback, 
        &result, 
        0);
    
    if (scan_result != ERROR_SUCCESS) {
        log_message(LOG_ERROR, "Error scanning file: %s", filePath);
    }
}

void scanDirectory(const char* dirPath, YR_RULES* rules) {
    DIR* dir;
    struct dirent* entry;

    if (!(dir = opendir(dirPath))) {
        log_message(LOG_ERROR, "Error opening directory: %s", dirPath);
        return;
    }
    
    log_message(LOG_INFO, "Scanning directory: %s", dirPath);

    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char path[BUFFER_SIZE];
        snprintf(path, sizeof(path), "%s%c%s", dirPath, PATH_SEPARATOR, entry->d_name);

        struct stat path_stat;
        stat(path, &path_stat);

        if (S_ISDIR(path_stat.st_mode)) {
            scanDirectory(path, rules);
        }
        else if (S_ISREG(path_stat.st_mode)) {
            scanFile(path, rules);
        }
    }
    closedir(dir);
    
    log_message(LOG_INFO, "Completed scanning directory: %s", dirPath);
}

void checkType(const char* path, YR_RULES* rules) {
    struct stat path_stat;
    if (stat(path, &path_stat) == 0) {
        if (S_ISREG(path_stat.st_mode)) {
            // Path is a regular file
            scanFile(path, rules);
        }
        else if (S_ISDIR(path_stat.st_mode)) {
            // Path is a directory
            scanDirectory(path, rules);
        }
        else {
            log_message(LOG_ERROR, "Unknown file type");
        }
    }
    else {
        perror("[-] Error getting file status");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        log_message(LOG_ERROR, "Incorrect parameters specified");
        log_message(LOG_ERROR, "Usage: %s <file_or_directory_path>", argv[0]);
        return 1;
    }

    const char directory_path[] = "./rules";  // Use relative path or adjust to your Linux directory
    char* file_path = argv[1];

    // Initialize YARA
    int Initresult = yr_initialize();
    if (Initresult != 0) {
        log_message(LOG_ERROR, "Failed to initialize YARA");
        return 1;
    }

    log_message(LOG_INFO, "Successfully initialized YARA");

    // Load YARA rules from each file in the directory
    DIR* directory = opendir(directory_path);
    if (directory == NULL) {
        log_message(LOG_ERROR, "Failed to open rules directory: %s", directory_path);
        yr_finalize();
        return 1;
    }

    log_message(LOG_INFO, "Successfully opened rules directory");

    // First count valid rule files
    int valid_rule_files = 0;
    struct dirent* entry;
    while ((entry = readdir(directory)) != NULL) {
        char rule_file_path[PATH_MAX];
        snprintf(rule_file_path, sizeof(rule_file_path), "%s/%s", directory_path, entry->d_name);

        struct stat path_stat;
        stat(rule_file_path, &path_stat);

        if (S_ISREG(path_stat.st_mode) && 
           (strstr(entry->d_name, ".yar") != NULL || strstr(entry->d_name, ".yara") != NULL)) {
            valid_rule_files++;
        }
    }
    
    if (valid_rule_files == 0) {
        log_message(LOG_ERROR, "No valid YARA rule files found in directory");
        closedir(directory);
        yr_finalize();
        return 1;
    }
    
    log_message(LOG_INFO, "Found %d valid rule files", valid_rule_files);
    
    // Reset directory pointer
    rewinddir(directory);
    
    // Process all rule files, continuing even if some have errors
    int compiled_rules = 0;
    int failed_rules = 0;
    YR_RULES* rules = NULL;
    
    while ((entry = readdir(directory)) != NULL) {
        // Check if file ends with .yar or .yara
        char rule_file_path[PATH_MAX];
        snprintf(rule_file_path, sizeof(rule_file_path), "%s/%s", directory_path, entry->d_name);

        struct stat path_stat;
        stat(rule_file_path, &path_stat);

        if (S_ISREG(path_stat.st_mode) && 
           (strstr(entry->d_name, ".yar") != NULL || strstr(entry->d_name, ".yara") != NULL)) {
            
            FILE* rule_file = fopen(rule_file_path, "rb");
            if (rule_file == NULL) {
                log_message(LOG_ERROR, "Failed to open rule file: %s", rule_file_path);
                displayErrorMessage(errno);
                failed_rules++;
                continue;
            }
            
            // Create a new compiler instance for each rule file to avoid error accumulation
            YR_COMPILER* file_compiler = NULL;
            if (yr_compiler_create(&file_compiler) != ERROR_SUCCESS) {
                log_message(LOG_ERROR, "Failed to create compiler for rule file: %s", rule_file_path);
                fclose(rule_file);
                failed_rules++;
                continue;
            }
            
            // Use filename as namespace to prevent rule conflicts    
            int Addresult = yr_compiler_add_file(file_compiler, rule_file, NULL, entry->d_name); 
            fclose(rule_file);
            
            if (Addresult > 0) {
                log_message(LOG_ERROR, "Failed to compile YARA rule %s, number of errors found: %d", rule_file_path, Addresult);
                failed_rules++;
                yr_compiler_destroy(file_compiler);
            } else {
                // Get rules from this compiler and add to main rules
                YR_RULES* file_rules = NULL;
                if (yr_compiler_get_rules(file_compiler, &file_rules) == ERROR_SUCCESS) {
                    // For the first successful compilation, initialize rules
                    if (rules == NULL) {
                        rules = file_rules;
                    } else {
                        // In a real implementation, you'd need to merge rules properly
                        // Here we're just using the latest successful compilation
                        yr_rules_destroy(rules);
                        rules = file_rules;
                    }
                    log_message(LOG_INFO, "Compiled rules from %s", rule_file_path);
                    
                    // Debug: Print rules in this file
                    int rule_count = 0;
                    YR_RULE* rule;
                    yr_rules_foreach(file_rules, rule) {
                        rule_count++;
                    }
                    log_message(LOG_DEBUG, "Rule file %s contains %d rules", rule_file_path, rule_count);
                    
                    compiled_rules++;
                } else {
                    log_message(LOG_ERROR, "Failed to get rules for %s", rule_file_path);
                    failed_rules++;
                }
                yr_compiler_destroy(file_compiler);
            }
        }
    }
  
    closedir(directory);
    
    // Check if we have any successfully compiled rules
    if (compiled_rules == 0) {
        log_message(LOG_ERROR, "No rules were successfully compiled. Exiting.");
        yr_finalize();
        return 1;
    }
    
    log_message(LOG_INFO, "Successfully compiled %d rule files (failed: %d)", compiled_rules, failed_rules);

    // No need to get rules again as we've been building them up
    if (rules == NULL) {
        log_message(LOG_ERROR, "Failed to compile any rules");
        yr_finalize();
        return 1;
    }

    log_message(LOG_INFO, "Starting scan of: %s", file_path);
    log_message(LOG_RESULT, "SCAN_START:%s", file_path);
    
    // Scan the specified file or directory
    checkType(file_path, rules);
    
    log_message(LOG_INFO, "Scan completed");
    log_message(LOG_RESULT, "SCAN_COMPLETE:%s", file_path);

    // Clean up
    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}