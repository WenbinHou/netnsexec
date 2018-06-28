#ifndef __NETNSEXEC_H_INCLUDED__
#define __NETNSEXEC_H_INCLUDED__



struct cmd_options {
    int verbose;
    char* str_uid;
    char* str_gid;
    unsigned uid;
    unsigned gid;
    char* workdir;
    char* pidfile;
    char* netns;
    int lo_up;
};
typedef struct cmd_options cmd_options;


#endif // __NETNSEXEC_H_INCLUDED__
