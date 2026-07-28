#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <archive.h>
#include <archive_entry.h>
#include <zstd.h>
#include <pthread.h>
#include <curl/curl.h>
#include <fcntl.h>

#define MAX_LINE 8192
#define MAX_CMD 4096
#define MAX_PATH 1024
#define MAX_PACKAGES 10000
#define MAX_VERSIONS 100

typedef struct {
    char name[256];
    char fetch[1024];
    char version[64];
    char instructions[MAX_CMD];
    int has_instructions;
    char versions_fetch[10][1024];
    char versions_tag[10][64];
    int version_count;
    char tar_files[256];
    int is_tar;
} Package;

typedef struct {
    char name[256];
    char git_url[1024];
    char last_commit[64];
} PackageUpdate;

Package packages[MAX_PACKAGES];
int package_count = 0;
char repo_path[MAX_PATH] = "";
char home_dir[MAX_PATH];
char decompressed_repo[MAX_PATH];

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream) {
    FILE *fp = (FILE *)stream;
    return fwrite(ptr, size, nmemb, fp);
}

int download_file(const char *url, const char *output_path) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    
    FILE *fp = fopen(output_path, "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10);
    curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 65536);
    
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK) ? 0 : -1;
}

void extract_tar_zstd(const char *archive_path, const char *dest_dir) {
    struct archive *a = archive_read_new();
    archive_read_support_filter_zstd(a);
    archive_read_support_format_tar(a);
    
    if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to open archive: %s\n", archive_path);
        return;
    }
    
    mkdir(dest_dir, 0755);
    
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dest_dir, archive_entry_pathname(entry));
        
        if (archive_entry_filetype(entry) == AE_IFDIR) {
            mkdir(full_path, 0755);
        } else {
            char dir_path[MAX_PATH];
            strcpy(dir_path, full_path);
            char *parent = dirname(dir_path);
            mkdir(parent, 0755);
            
            int fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                archive_read_data_into_fd(a, fd);
                close(fd);
            }
        }
    }
    archive_read_close(a);
    archive_read_free(a);
}

void parse_packages_file(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return;
    
    char line[MAX_LINE];
    Package *current = NULL;
    int in_instructions = 0;
    int in_versions = 0;
    
    package_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;
        
        if (strncmp(line, "start_", 6) == 0) {
            current = &packages[package_count];
            memset(current, 0, sizeof(Package));
            sscanf(line, "start_%[^\n]", current->name);
            in_instructions = 0;
            in_versions = 0;
        } else if (strncmp(line, "end_", 4) == 0) {
            if (current) {
                package_count++;
                current = NULL;
            }
        } else if (line[0] == '"' && current) {
            char name[256], fetch[1024];
            if (sscanf(line, "\"%[^\"]\" fetch=%s", name, fetch) == 2) {
                strcpy(current->name, name);
                strcpy(current->fetch, fetch);
            } else if (sscanf(line, "\"%[^\"]\" fetch=%[^\n]", name, fetch) == 2) {
                strcpy(current->name, name);
                strcpy(current->fetch, fetch);
            }
        } else if (strcmp(line, "[instructions]") == 0 && current) {
            in_instructions = 1;
            current->has_instructions = 1;
            current->instructions[0] = 0;
        } else if (strcmp(line, "[versions]") == 0 && current) {
            in_versions = 1;
            in_instructions = 0;
            current->version_count = 0;
        } else if (strcmp(line, "[tar_files]") == 0 && current) {
            current->is_tar = 1;
        } else if (strncmp(line, "tar_files=", 10) == 0 && current) {
            strcpy(current->tar_files, line + 10);
            current->is_tar = 1;
        } else if (in_instructions && current) {
            if (strlen(current->instructions) > 0) {
                strcat(current->instructions, "\n");
            }
            strcat(current->instructions, line);
        } else if (in_versions && current) {
            char tag[64], url[1024];
            if (sscanf(line, "%s %s", tag, url) == 2) {
                if (current->version_count < 10) {
                    strcpy(current->versions_tag[current->version_count], tag);
                    strcpy(current->versions_fetch[current->version_count], url);
                    current->version_count++;
                }
            }
        }
    }
    fclose(fp);
}

void decompress_repository(const char *tar_path, const char *dest_dir) {
    mkdir(dest_dir, 0755);
    extract_tar_zstd(tar_path, dest_dir);
    
    char packages_file[MAX_PATH];
    snprintf(packages_file, sizeof(packages_file), "%s/packages.txt", dest_dir);
    parse_packages_file(packages_file);
}

void init_bux() {
    strcpy(home_dir, getenv("HOME"));
    char bux_dir[MAX_PATH];
    snprintf(bux_dir, sizeof(bux_dir), "%s/.bux", home_dir);
    mkdir(bux_dir, 0755);
}

void set_repository(const char *repo_name) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s/.bux/%s", home_dir, repo_name);
    
    if (access(full_path, F_OK) != 0) {
        fprintf(stderr, "Repository directory not found: %s\n", full_path);
        return;
    }
    
    strcpy(repo_path, full_path);
    
    char packages_file[MAX_PATH];
    snprintf(packages_file, sizeof(packages_file), "%s/packages.txt", repo_path);
    
    if (access(packages_file, F_OK) != 0) {
        char tar_file[MAX_PATH];
        snprintf(tar_file, sizeof(tar_file), "%s.tar.zstd", repo_path);
        
        if (access(tar_file, F_OK) == 0) {
            snprintf(decompressed_repo, sizeof(decompressed_repo), "%s/.bux/%s_decomp", home_dir, repo_name);
            decompress_repository(tar_file, decompressed_repo);
            snprintf(packages_file, sizeof(packages_file), "%s/packages.txt", decompressed_repo);
        } else {
            fprintf(stderr, "No packages.txt or tar.zstd found\n");
            return;
        }
    } else {
        parse_packages_file(packages_file);
        strcpy(decompressed_repo, repo_path);
    }
    
    printf("Repository set to %s\n", repo_path);
}

Package* find_package(const char *name) {
    for (int i = 0; i < package_count; i++) {
        if (strcmp(packages[i].name, name) == 0) {
            return &packages[i];
        }
    }
    return NULL;
}

int execute_command(const char *cmd) {
    return system(cmd);
}

void execute_instructions(const char *instructions) {
    char *cmd_copy = strdup(instructions);
    char *cmd = strtok(cmd_copy, "\n");
    
    while (cmd) {
        while (*cmd == ' ' || *cmd == '\t') cmd++;
        if (strlen(cmd) > 0) {
            printf("Running: %s\n", cmd);
            int ret = system(cmd);
            if (ret != 0) {
                fprintf(stderr, "Command failed with code %d\n", ret);
            }
        }
        cmd = strtok(NULL, "\n");
    }
    free(cmd_copy);
}

int install_package(const char *name, const char *version) {
    Package *pkg = find_package(name);
    if (!pkg) {
        fprintf(stderr, "Package '%s' not found\n", name);
        return -1;
    }
    
    char cache_dir[MAX_PATH];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.bux/cache/%s", home_dir, name);
    mkdir(cache_dir, 0755);
    
    const char *fetch_url = pkg->fetch;
    if (version) {
        for (int i = 0; i < pkg->version_count; i++) {
            if (strcmp(pkg->versions_tag[i], version) == 0) {
                fetch_url = pkg->versions_fetch[i];
                break;
            }
        }
    }
    
    char download_path[MAX_PATH];
    snprintf(download_path, sizeof(download_path), "%s/download", cache_dir);
    
    printf("Downloading %s from %s...\n", name, fetch_url);
    if (download_file(fetch_url, download_path) != 0) {
        fprintf(stderr, "Download failed\n");
        return -1;
    }
    
    if (pkg->is_tar) {
        char extract_dir[MAX_PATH];
        snprintf(extract_dir, sizeof(extract_dir), "%s/extracted", cache_dir);
        mkdir(extract_dir, 0755);
        extract_tar_zstd(download_path, extract_dir);
        
        char *files_copy = strdup(pkg->tar_files);
        char *token = strtok(files_copy, " ");
        while (token) {
            char src[MAX_PATH], dst[MAX_PATH];
            snprintf(src, sizeof(src), "%s/%s", extract_dir, token);
            snprintf(dst, sizeof(dst), "%s/%s", cache_dir, basename(token));
            char cmd[MAX_CMD];
            snprintf(cmd, sizeof(cmd), "cp -r %s %s", src, dst);
            system(cmd);
            token = strtok(NULL, " ");
        }
        free(files_copy);
    }
    
    if (pkg->has_instructions) {
        char cwd[MAX_PATH];
        getcwd(cwd, sizeof(cwd));
        chdir(cache_dir);
        execute_instructions(pkg->instructions);
        chdir(cwd);
    }
    
    printf("Package '%s' installed successfully\n", name);
    return 0;
}

void remove_package(const char *name) {
    char cache_dir[MAX_PATH];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.bux/cache/%s", home_dir, name);
    
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cache_dir);
    system(cmd);
    
    printf("Package '%s' removed\n", name);
}

typedef struct {
    char url[1024];
    char output[1024];
} DownloadJob;

void* parallel_download(void *arg) {
    DownloadJob *job = (DownloadJob *)arg;
    download_file(job->url, job->output);
    return NULL;
}

void install_max() {
    printf("Max downloader installed. Usage: max <url1,url2,...>\n");
}

void run_max(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: max <url1,url2,...>\n");
        return;
    }
    
    char *urls = argv[2];
    char *urls_copy = strdup(urls);
    char *token = strtok(urls_copy, ",");
    
    int url_count = 0;
    char *url_list[100];
    
    while (token && url_count < 100) {
        while (*token == ' ') token++;
        url_list[url_count++] = token;
        token = strtok(NULL, ",");
    }
    
    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    
    pthread_t threads[url_count];
    DownloadJob jobs[url_count];
    
    for (int i = 0; i < url_count; i++) {
        strcpy(jobs[i].url, url_list[i]);
        char filename[256];
        snprintf(filename, sizeof(filename), "download_%d", i);
        strcpy(jobs[i].output, filename);
        pthread_create(&threads[i], NULL, parallel_download, &jobs[i]);
    }
    
    for (int i = 0; i < url_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("All downloads completed\n");
    free(urls_copy);
}

void install_dist() {
    printf("Distribution chroot tool installed. Usage: dist <rootfs_path>\n");
}

void run_dist(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: dist <rootfs_path>\n");
        return;
    }
    
    char *target = argv[2];
    
    if (access(target, F_OK) != 0) {
        fprintf(stderr, "Rootfs path does not exist: %s\n", target);
        return;
    }
    
    char distro_type[64] = "alpine";
    char *target_basename = basename(target);
    
    if (strstr(target_basename, "ubuntu") || strstr(target_basename, "debian")) {
        strcpy(distro_type, "debian");
    } else if (strstr(target_basename, "arch")) {
        strcpy(distro_type, "arch");
    } else if (strstr(target_basename, "void")) {
        strcpy(distro_type, "void");
    } else if (strstr(target_basename, "alpine")) {
        strcpy(distro_type, "alpine");
    }
    
    printf("Entering %s chroot at %s\n", distro_type, target);
    
    char mount_cmd[MAX_CMD];
    snprintf(mount_cmd, sizeof(mount_cmd), "mount -t proc proc %s/proc", target);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "mount -t sysfs sys %s/sys", target);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "mount -o bind /dev %s/dev", target);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "mount -o bind /dev/pts %s/dev/pts", target);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "cp /etc/resolv.conf %s/etc/resolv.conf", target);
    system(mount_cmd);
    
    char shell[64] = "/bin/bash";
    if (strcmp(distro_type, "alpine") == 0) {
        strcpy(shell, "/bin/ash");
    } else if (strcmp(distro_type, "arch") == 0 || strcmp(distro_type, "void") == 0) {
        strcpy(shell, "/bin/bash");
    }
    
    snprintf(mount_cmd, sizeof(mount_cmd), "chroot %s %s", target, shell);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "umount %s/proc", target);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "umount %s/sys", target);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "umount %s/dev/pts", target);
    system(mount_cmd);
    
    snprintf(mount_cmd, sizeof(mount_cmd), "umount %s/dev", target);
    system(mount_cmd);
    
    printf("Exited chroot\n");
}

void install_sandbox() {
    printf("Sandbox installed. Usage: sandbox\n");
}

void run_sandbox() {
    printf("Entering sandboxed shell...\n");
    
    if (fork() == 0) {
        chroot("/tmp/sandbox");
        chdir("/");
        execl("/bin/sh", "/bin/sh", NULL);
        exit(0);
    } else {
        wait(NULL);
    }
    printf("Exited sandbox\n");
}

void install_audi() {
    printf("Audi terminal manager installed. Usage: audi start <name> [--testing]\n");
}

void run_audi(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: audi start <terminal_name> [--testing]\n");
        return;
    }
    
    if (strcmp(argv[2], "start") != 0) {
        fprintf(stderr, "Unknown command\n");
        return;
    }
    
    if (argc < 4) {
        fprintf(stderr, "Terminal name required\n");
        return;
    }
    
    char *term_name = argv[3];
    int testing = 0;
    
    if (argc >= 5 && strcmp(argv[4], "--testing") == 0) {
        testing = 1;
    }
    
    char term_dir[MAX_PATH];
    snprintf(term_dir, sizeof(term_dir), "/tmp/audi_%s", term_name);
    mkdir(term_dir, 0755);
    
    if (testing) {
        printf("Starting Docker-based testing terminal: %s\n", term_name);
        char cmd[MAX_CMD];
        snprintf(cmd, sizeof(cmd), "docker run -it --name audi_%s alpine /bin/sh", term_name);
        system(cmd);
    } else {
        printf("Starting isolated terminal: %s\n", term_name);
        
        if (fork() == 0) {
            mkdir(term_dir, 0755);
            chroot(term_dir);
            chdir("/");
            
            mkdir("/tmp", 0755);
            mkdir("/dev", 0755);
            mkdir("/proc", 0755);
            mkdir("/sys", 0755);
            
            mount("proc", "/proc", "proc", 0, NULL);
            mount("sysfs", "/sys", "sysfs", 0, NULL);
            
            execl("/bin/sh", "/bin/sh", NULL);
            exit(0);
        } else {
            wait(NULL);
        }
    }
}

void run_builtin(int argc, char **argv) {
    if (strcmp(argv[1], "max") == 0) {
        run_max(argc, argv);
    } else if (strcmp(argv[1], "dist") == 0) {
        run_dist(argc, argv);
    } else if (strcmp(argv[1], "sandbox") == 0) {
        run_sandbox();
    } else if (strcmp(argv[1], "audi") == 0) {
        run_audi(argc, argv);
    }
}

void check_updates(Package *pkg) {
    if (!pkg) return;
    
    char update_check[MAX_CMD];
    snprintf(update_check, sizeof(update_check), "cd /tmp && git ls-remote %s HEAD", pkg->fetch);
    
    FILE *fp = popen(update_check, "r");
    if (fp) {
        char commit[128];
        if (fgets(commit, sizeof(commit), fp)) {
            char current_commit[128] = "";
            char update_file[MAX_PATH];
            snprintf(update_file, sizeof(update_file), "%s/.bux/updates/%s", home_dir, pkg->name);
            
            FILE *uf = fopen(update_file, "r");
            if (uf) {
                fgets(current_commit, sizeof(current_commit), uf);
                fclose(uf);
            }
            
            if (strlen(current_commit) > 0 && strncmp(commit, current_commit, 40) != 0) {
                printf("Update available for %s\n", pkg->name);
            }
            
            uf = fopen(update_file, "w");
            if (uf) {
                fprintf(uf, "%s", commit);
                fclose(uf);
            }
        }
        pclose(fp);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: bux <command> [args]\n");
        fprintf(stderr, "Commands: set, i, r, d, up, max, dist, sandbox, audi\n");
        return 1;
    }
    
    init_bux();
    
    if (strcmp(argv[1], "set") == 0 && argc >= 3) {
        set_repository(argv[2]);
    } else if (strcmp(argv[1], "i") == 0 && argc >= 3) {
        if (strcmp(argv[2], "max") == 0) {
            install_max();
        } else if (strcmp(argv[2], "dist") == 0) {
            install_dist();
        } else if (strcmp(argv[2], "sandbox") == 0) {
            install_sandbox();
        } else if (strcmp(argv[2], "audi") == 0) {
            install_audi();
        } else {
            const char *version = argc >= 4 ? argv[3] : NULL;
            install_package(argv[2], version);
        }
    } else if (strcmp(argv[1], "r") == 0 && argc >= 3) {
        printf("Reinstalling %s...\n", argv[2]);
        install_package(argv[2], NULL);
    } else if (strcmp(argv[1], "d") == 0 && argc >= 3) {
        remove_package(argv[2]);
    } else if (strcmp(argv[1], "up") == 0 && argc >= 3) {
        Package *pkg = find_package(argv[2]);
        if (pkg) {
            check_updates(pkg);
            install_package(argv[2], NULL);
        }
    } else if (strcmp(argv[1], "max") == 0 || strcmp(argv[1], "dist") == 0 || 
               strcmp(argv[1], "sandbox") == 0 || strcmp(argv[1], "audi") == 0) {
        run_builtin(argc, argv);
    }
    
    return 0;
}
