#define _GNU_SOURCE

#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <wait.h>
#include "netnsexec.h"
#include "version.h"


void usage(int exit_code)
{
    printf("netnsexec [options] <netns> [--] <program> ...\n"
           "\n"
           "options:\n"
           "    -h, --help              Show help text and exit\n"
           "    -V, --version           Show version and exit\n"
           "    -v, --verbose           Be verbose\n"
           "    -u, --uid <uid>         Run as specific user (root only)\n"
           "    -g, --gid <gid>         Run as specific group (root only)\n"
           "    -w, --cd <workdir>      Change to specific working directory JUST BEFORE exec\n"
           "    -f, --pidfile <file>    Write a pid file (Not affected by --cd if specified)\n"
           "    --lo                    Try to bring up 'lo' interface first\n"
           "\n"
           "netns:\n"
           "    self                    Don't change network namespace\n"
           "    unshare                 Create a new network namespace\n"
           "    default                 /proc/1/ns/net (restricted to current pid namespace)\n"
           "    <abs_netns_path>        Absolute path (starting with '/') of netns file\n"
           "    iproute2/<name>         Short for /var/run/netns/<name>\n"
           "    proc/<xxx>              Short for /proc/<xxx>/ns/net (xxx could be pid, tid, \"self\")\n"
           "    docker/<container>      Use 'docker inspect' to obtain its network space\n"
           "\n");
    exit(exit_code);
}

int parse_options(cmd_options* options, int argc, char** argv)
{
    int idx;

    memset(options, 0x00, sizeof(*options));

    for (idx = 1; idx < argc; ++idx) {

        if (argv[idx][0] == '-') {

            if (strcmp(argv[idx], "--") == 0) {
                ++idx;
                break;
            }
            if (strcmp(argv[idx], "-h") == 0 || strcmp(argv[idx], "--help") == 0) {
                usage(0);
            }
            else if (strcmp(argv[idx], "-V") == 0 || strcmp(argv[idx], "--version") == 0) {
                printf("%d.%d.%d\n", NETNSEXEC_VERSION_MAJOR, NETNSEXEC_VERSION_MINOR, NETNSEXEC_VERSION_PATCH);
                exit(0);
            }
            else if (strcmp(argv[idx], "-u") == 0 || strcmp(argv[idx], "--uid") == 0) {
                if (idx == argc - 1) {
                    fprintf(stderr, "User is not specified after '%s\n'", argv[idx]);
                    exit(1);
                }
                options->str_uid = argv[++idx];
            }
            else if (strcmp(argv[idx], "-g") == 0 || strcmp(argv[idx], "--gid") == 0) {
                if (idx == argc - 1) {
                    fprintf(stderr, "Group is not specified after '%s\n'", argv[idx]);
                    exit(1);
                }
                options->str_gid = argv[++idx];
            }
            else if (strcmp(argv[idx], "-v") == 0 || strcmp(argv[idx], "--verbose") == 0) {
                ++options->verbose;
            }
            else if (strcmp(argv[idx], "-w") == 0 || strcmp(argv[idx], "--cd") == 0) {
                if (idx == argc - 1) {
                    fprintf(stderr, "Working directory is not specified after '%s\n'", argv[idx]);
                    exit(1);
                }
                options->workdir = argv[++idx];
            }
            else if (strcmp(argv[idx], "-f") == 0 || strcmp(argv[idx], "--pidfile") == 0) {
                if (idx == argc - 1) {
                    fprintf(stderr, "PID file is not specified after '%s\n'", argv[idx]);
                    exit(1);
                }
                options->pidfile = argv[++idx];
            }
            else if (strcmp(argv[idx], "--lo") == 0) {
                options->lo_up = 1;
            }
            else {
                fprintf(stderr, "Unknown option: %s\n", argv[idx]);
                exit(1);
            }
        }
        else {  /* argv[idx][0] != '-', which means this is the netns or program */
            if (options->netns) {
                break;
            }
            options->netns = argv[idx];
        }
    }

    if (!options->netns) {
        fprintf(stderr, "Network namespace and program to execute are not specified.\n");
        exit(1);
    }

    if (idx == argc) {
        fprintf(stderr, "Program to execute is not specified.\n");
        exit(1);
    }

    if (options->str_uid) {
        char* endptr;
        unsigned long uid = strtoul(options->str_uid, &endptr, 10);
        const int err = errno;
        if (*endptr != '\0' || err == ERANGE || err == EINVAL || uid > (unsigned)-1) {
            fprintf(stderr, "Invalid UID: %s\n", options->str_uid);
            exit(!err ? err : 2);
        }
        options->uid = (unsigned)uid;

        if (options->verbose) {
            printf("Switch to UID: %u\n", options->uid);
        }
    }

    if (options->str_gid) {
        char* endptr;
        unsigned long gid = strtoul(options->str_gid, &endptr, 10);
        const int err = errno;
        if (*endptr != '\0' || err == ERANGE || err == EINVAL || gid > (unsigned)-1) {
            fprintf(stderr, "Invalid GID: %s\n", options->str_gid);
            exit(!err ? err : 2);
        }
        options->gid = (unsigned)gid;

        if (options->verbose) {
            printf("Switch to GID: %u\n", options->gid);
        }
    }

    if (options->verbose) {
        if (options->lo_up) {
            printf("Try to bring up 'lo' interface\n");
        }
    }

    return idx;
}

int my_unshare(int flags)
{
    return (int)syscall(__NR_unshare, flags);
}

int my_setns(int fd, int nstype)
{
    return (int)syscall(__NR_setns, fd, nstype);
}

void write_pidfile(const char* pidfile)
{
    int fd = open(pidfile, O_CREAT|O_TRUNC|O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Can't open() pidfile %s: %s (%d)\n", pidfile, strerror(errno), errno);
        exit(errno);
    }

    char pid[16];
    sprintf(pid, "%ld", (long int)getpid());

    size_t len = strlen(pid);
    if (write(fd, pid, len) != len) {
        fprintf(stderr, "Can't or partially write() pidfile %s: %s (%d)\n", pidfile, strerror(errno), errno);
        close(fd);
        exit(errno);
    }

    if (fchmod(fd, 0644) < 0) {
        fprintf(stderr, "Can't or chmod(0644) pidfile %s: %s (%d)\n", pidfile, strerror(errno), errno);
        close(fd);
        exit(errno);
    }

    close(fd);
}

int launch(char* const* argv, FILE** cout, FILE** cerr)
{
    int pipeout[2];
    int pipeerr[2];

    if (cout && pipe(pipeout) < 0) {
        fprintf(stderr, "pipe(pipeout) failed: %s (%d)\n", strerror(errno), errno);
        exit(errno);
    }

    if (cerr && pipe(pipeerr) < 0) {
        fprintf(stderr, "pipe(pipeerr) failed: %s (%d)\n", strerror(errno), errno);
        exit(errno);
    }

    int pid = fork();
    if (pid == 0) {  // child
        if (cout) {
            dup2(pipeout[1], STDOUT_FILENO);
            close(pipeout[0]);
            close(pipeout[1]);
        }
        if (cerr) {
            dup2(pipeerr[1], STDERR_FILENO);
            close(pipeerr[0]);
            close(pipeerr[1]);
        }

        if (execvp(argv[0], argv) < 0) {
            exit(errno);
        }
    }
    else {  // parent
        int status;

        if (cout) {
            close(pipeout[1]);
            *cout = fdopen(pipeout[0], "r");
        }
        if (cerr) {
            close(pipeerr[1]);
            *cerr = fdopen(pipeerr[0], "r");
        }

        if (waitpid(pid, &status, 0) < 0) {
            fprintf(stderr, "waitpid(%d) failed: %s (%d)\n", pid, strerror(errno), errno);
            exit(errno);
        }

        return status;
    }
}

void set_netns(const char* netns)
{
    const char* PREFIX_IPROUTE2 = "iproute2/";
    const char* PREFIX_PROC = "proc/";
    const char* PREFIX_DOCKER = "docker/";
    char* nsfile;
    int fd, ret;

    if (strcmp(netns, "self") == 0) {
        return;
    }
    else if (strcmp(netns, "unshare") == 0) {
        if (my_unshare(CLONE_NEWNET) < 0) {
            fprintf(stderr, "unshare(CLONE_NEWNET) error: %s (%d)\n", strerror(errno), errno);
            exit(errno);
        }
        return;
    }


    nsfile = (char*)malloc(strlen(netns) + 32);
    if (!nsfile) {
        fprintf(stderr, "Out of memory\n");
        exit(2);
    }

    if (netns[0] == '/') {
        strcpy(nsfile, netns);
    }
    else if (strcmp(netns, "default") == 0) {
        strcpy(nsfile, "/proc/1/ns/net");
    }
    else if (strncmp(netns, PREFIX_IPROUTE2, strlen(PREFIX_IPROUTE2)) == 0) {
        sprintf(nsfile, "/var/run/netns/%s", netns + strlen(PREFIX_IPROUTE2));
    }
    else if (strncmp(netns, PREFIX_PROC, strlen(PREFIX_PROC)) == 0) {
        sprintf(nsfile, "/proc/%s/ns/net", netns + strlen(PREFIX_PROC));
    }
    else if (strncmp(netns, PREFIX_DOCKER, strlen(PREFIX_DOCKER)) == 0) {
        char* argv[] = {
            "docker",
            "inspect",
            "--format",
            "{{.State.Pid}}",
            (char*)(netns + strlen(PREFIX_DOCKER)),
            NULL
        };
        FILE* dockerout;
        int status = launch(argv, &dockerout, NULL) & 0xFF;
        if (status != 0) {
            fprintf(stderr, "Launch docker inspect returns %d: %s\n", status, strerror(status));
            exit(status);
        }

        unsigned pid;
        if (fscanf(dockerout, "%u", &pid) != 1) {
            fprintf(stderr, "docker inspect didn't respond a valid pid\n");
            exit(2);
        }

        sprintf(nsfile, "/proc/%u/ns/net", pid);
    }
    else {
        fprintf(stderr, "Unknown netns: %s\n", netns);
        free(nsfile);
        exit(2);
    }

    fd = open(nsfile, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(\"%s\") failed: %s (%d)\n", nsfile, strerror(errno), errno);
        free(nsfile);
        exit(errno);
    }

    free(nsfile);

    ret = my_setns(fd, CLONE_NEWNET);
    close(fd);

    if (ret < 0) {
        fprintf(stderr, "setns() failed: %s (%d)\n", strerror(errno), errno);
        exit(errno);
    }
}

void setup_lo_interface(cmd_options *options)
{
    char* const argv[] = {"ip", "link", "set", "dev", "lo", "up", NULL};
    int ret;
    if (options->verbose) {
        printf("Command: ip link set dev lo up\n");
    }
    ret = launch(argv, NULL, NULL);
    if ((ret & 0xFF) != 0) {
        /* attempt ifconfig */
        char* const argv2[] = {"ifconfig", "lo", "up", NULL};
        if (options->verbose) {
            printf("Command: ifconfig lo up\n");
        }
        ret = launch(argv2, NULL, NULL);
        if ((ret & 0xFF) != 0) {
            fprintf(stderr, "Can't bring up lo interface.\n"
                            "Is 'ip' or 'ifconfig' installed? Is your euid root?\n");
            exit(2);
        }
    }
}

int main(int argc, char** argv)
{
    int i;
    cmd_options options;

    errno = 0;

    /* Parse command line arguments */
    int program_at = parse_options(&options, argc, argv);

    /* Write pid file if required */
    if (options.pidfile) {
        write_pidfile(options.pidfile);
        if (options.str_uid || options.str_gid) {
            unsigned uid = options.str_uid ? options.uid : getuid();    // TODO: getuid() or geteuid() ?
            unsigned gid = options.str_gid ? options.gid : getgid();    // TODO:
            if (chown(options.pidfile, uid, gid) < 0) {
                fprintf(stderr, "Can't chown() pidfile %s: %s (%d)\n", options.pidfile, strerror(errno), errno);
                exit(errno);
            }
        }
    }

    /* Change to specific network namespace */
    set_netns(options.netns);

    /* Setup lo if required */
    if (options.lo_up) {
        setup_lo_interface(&options);
    }

    /* Switch to specific user & group if required */
    if (options.str_gid) {
        if (setgid(options.gid) < 0) {
            fprintf(stderr, "Can't setgid(%d): %s (%d)\n", options.gid, strerror(errno), errno);
            exit(errno);
        }
    }
    else if (getegid() != getgid()) {
        setegid(getgid());
    }

    if (options.str_uid) {
        if (setuid(options.uid) < 0) {
            fprintf(stderr, "Can't setuid(%d): %s (%d)\n", options.uid, strerror(errno), errno);
            exit(errno);
        }
    }
    else if (geteuid() != getuid()) {
        seteuid(getuid());
    }

    if (options.verbose) {
        printf("Exec as - uid: %u, euid: %u, gid: %u, egid: %u\n", getuid(), geteuid(), getgid(), getegid());
    }

    /* Change to specific directory */
    if (options.workdir) {
        if (chdir(options.workdir) < 0) {
            fprintf(stderr, "Can't chdir(%s): %s (%d)\n", options.workdir, strerror(errno), errno);
            exit(errno);
        }
    }

    /* Execute the program */
    for (i = program_at; i < argc; ++i) {
        argv[i - program_at] = argv[i];
    }
    argv[argc - program_at] = NULL;

    int ret = execvp(argv[0], &argv[0]);

    fprintf(stderr, "Can't exec %s: %s (%d)\n", argv[0], strerror(errno), errno);
    return ret;
}
