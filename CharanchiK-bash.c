#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>

#define BUF_SIZE 8192
#define MAX_ARGS 64

struct intCmd {
    char *int_name;
    int  int_arg;
    void (*int_func)(char **);
};

void echo(char **), ls_cmd(char **), date_cmd(char **), pwd_cmd(char **);
void cd_cmd(char **), salir(char **), mkdir_cmd(char **), rm_cmd(char **);
void cp_cmd(char **), mv_cmd(char **), cat_cmd(char **);
void handle_sigchld(int sig);

struct intCmd internals[] = {
    { "echo",  1, echo },
    { "ls",    1, ls_cmd },
    { "date",  0, date_cmd },
    { "pwd",   0, pwd_cmd },
    { "cd",    1, cd_cmd },
    { "mkdir", 1, mkdir_cmd },
    { "rm",    1, rm_cmd },
    { "cp",    1, cp_cmd },
    { "mv",    1, mv_cmd },
    { "cat",   1, cat_cmd },
    { "exit",  0, salir },
    { 0, 0, 0 },
};

struct linux_dirent {
    long           d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

int main(int argc, char *argv[], char *envp[]) {
    int pid, is_int, background;
    int status;
    char buf[1024], *cmd, *arg;
    char *args[MAX_ARGS];
    int redir_in = -1, redir_out = -1, append_mode = 0;

    signal(SIGCHLD, handle_sigchld);

    write(1, "\033[2J\033[H", 7);
    write(1, "BASH> ", 6);

    while (fgets(buf, sizeof(buf), stdin)) {
        is_int = 0;
        background = 0;
        redir_in = -1;
        redir_out = -1;
        append_mode = 0;

        buf[strlen(buf)-1] = 0;

        if (strlen(buf) == 0) {
            write(1, "BASH> ", 6);
            continue;
        }


        cmd = strtok(buf, " ");
        if (!cmd) {
            write(1, "BASH> ", 6);
            continue;
        }
        int i = 0;
        args[i++] = cmd;

        while ((arg = strtok(NULL, " ")) != NULL && i < MAX_ARGS - 1) {
            if (strcmp(arg, "&") == 0) {
                background = 1;
            } else if (strcmp(arg, "<") == 0) {
                arg = strtok(NULL, " ");
                if (arg) redir_in = open(arg, O_RDONLY);
            } else if (strcmp(arg, ">") == 0) {
                arg = strtok(NULL, " ");
                if (arg) redir_out = open(arg, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            } else if (strcmp(arg, ">>") == 0) {
                arg = strtok(NULL, " ");
                if (arg) {
                    redir_out = open(arg, O_WRONLY | O_CREAT | O_APPEND, 0644);
                    append_mode = 1;
                }
            } else {
                args[i++] = arg;
            }
        }
        args[i] = NULL;
        struct intCmd *pic;
        for (pic = &internals[0]; pic->int_name; ++pic) {
            if (!strcmp(args[0], pic->int_name)) {

                int saved_stdin = -1, saved_stdout = -1;
                if (redir_in >= 0) {
                    saved_stdin = dup(0);
                    dup2(redir_in, 0);
                    close(redir_in);
                }
                if (redir_out >= 0) {
                    saved_stdout = dup(1);
                    dup2(redir_out, 1);
                    close(redir_out);
                }

                if (pic->int_arg) pic->int_func(args);
                else pic->int_func(NULL);

                if (saved_stdin >= 0) {
                    dup2(saved_stdin, 0);
                    close(saved_stdin);
                }
                if (saved_stdout >= 0) {
                    dup2(saved_stdout, 1);
                    close(saved_stdout);
                }

                is_int = 1;
                break;
            }
        }

        if (is_int) {
            write(1, "BASH> ", 6);
            continue;
        }

        pid = fork();
        if (pid == 0) {

            if (redir_in >= 0) {
                dup2(redir_in, 0);
                close(redir_in);
            }
            if (redir_out >= 0) {
                dup2(redir_out, 1);
                close(redir_out);
            }

            execvp(args[0], args);
            perror("EXECVE");
            exit(2);
        } else if (pid > 0) {

            if (redir_in >= 0) close(redir_in);
            if (redir_out >= 0) close(redir_out);

            if (!background) {
                waitpid(pid, &status, 0);
                if (WIFEXITED(status)) {
                    printf("status: %d\n", WEXITSTATUS(status));
                }
            } else {
                printf("[Background] PID: %d\n", pid);
            }
        } else {
            perror("FORK");
        }

        write(1, "BASH> ", 6);
    }
    return 0;
}


void handle_sigchld(int sig) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
    }
}



void echo(char *args[]) {
    int i = 1;
    while (args[i]) {
        write(1, args[i], strlen(args[i]));
        if (args[i+1]) write(1, " ", 1);
        i++;
    }
    write(1, "\n", 1);
}

void date_cmd(char *args[]) {
    time_t now;
    char *timestr;
    time(&now);
    timestr = ctime(&now);
    write(1, timestr, strlen(timestr));
}

void pwd_cmd(char *args[]) {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        write(1, cwd, strlen(cwd));
        write(1, "\n", 1);
    } else {
        perror("getcwd");
    }
}

void cd_cmd(char *args[]) {
    if (!args[1]) {
        write(1, "cd: missing argument\n", 21);
        return;
    }
    if (chdir(args[1]) < 0) {
        perror("cd");
    }
}

void ls_cmd(char *args[]) {
    int fd, nread;
    char buf[BUF_SIZE];
    struct linux_dirent *d;
    int bpos;
    char d_type;
    char *path = args[1] ? args[1] : ".";

    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("ls");
        return;
    }

    while (1) {
        nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
        if (nread == -1) {
            perror("getdents");
            close(fd);
            return;
        }
        if (nread == 0) break;

        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent *)(buf + bpos);
            d_type = *(buf + bpos + d->d_reclen - 1);

            if (strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0) {
                write(1, d->d_name, strlen(d->d_name));
                if (d_type == DT_DIR) write(1, "/", 1);
                write(1, "  ", 2);
            }
            bpos += d->d_reclen;
        }
    }
    write(1, "\n", 1);
    close(fd);
}

void mkdir_cmd(char *args[]) {
    if (!args[1]) {
        write(1, "mkdir: missing operand\n", 23);
        return;
    }
    if (mkdir(args[1], 0755) < 0) {
        perror("mkdir");
    }
}

void rm_cmd(char *args[]) {
    if (!args[1]) {
        write(1, "rm: missing operand\n", 20);
        return;
    }

    struct stat st;
    if (stat(args[1], &st) < 0) {
        perror("rm");
        return;
    }

    if (S_ISDIR(st.st_mode)) {
        if (rmdir(args[1]) < 0) {
            perror("rm");
        }
    } else {
        if (unlink(args[1]) < 0) {
            perror("rm");
        }
    }
}

void cp_cmd(char *args[]) {
    if (!args[1] || !args[2]) {
        write(1, "cp: missing file operand\n", 25);
        return;
    }

    int fd_src, fd_dst;
    char buffer[BUF_SIZE];
    ssize_t nread;

    fd_src = open(args[1], O_RDONLY);
    if (fd_src < 0) {
        perror("cp: source");
        return;
    }

    fd_dst = open(args[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_dst < 0) {
        perror("cp: destination");
        close(fd_src);
        return;
    }

    while ((nread = read(fd_src, buffer, BUF_SIZE)) > 0) {
        if (write(fd_dst, buffer, nread) != nread) {
            perror("cp: write");
            close(fd_src);
            close(fd_dst);
            return;
        }
    }

    close(fd_src);
    close(fd_dst);
}

void mv_cmd(char *args[]) {
    if (!args[1] || !args[2]) {
        write(1, "mv: missing file operand\n", 25);
        return;
    }

    if (rename(args[1], args[2]) < 0) {
        perror("mv");
    }
}

void cat_cmd(char *args[]) {
    if (!args[1]) {
        write(1, "cat: missing file operand\n", 26);
        return;
    }

    int fd;
    char buffer[BUF_SIZE];
    ssize_t nread;

    fd = open(args[1], O_RDONLY);
    if (fd < 0) {
        perror("cat");
        return;
    }

    while ((nread = read(fd, buffer, BUF_SIZE)) > 0) {
        write(1, buffer, nread);
    }

    close(fd);
}

void salir(char *args[]) {
    exit(0);
}
