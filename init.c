#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#define ANSI_BOLD_WHITE   "\033[1;37m"
#define ANSI_BOLD_CYAN    "\033[1;36m"
#define ANSI_BOLD_MAGENTA "\033[1;35m"
#define ANSI_BOLD_YELLOW  "\033[1;33m"
#define ANSI_BOLD_GREEN   "\033[1;32m"
#define ANSI_BOLD_RED     "\033[1;31m"
#define ANSI_RESET        "\033[0m"

// ANSI_BOLD_YELLOW
#define BASH_PS1 "\\[\\033[1;33m\\]\\$\\[\\033[0m\\] "

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <kbdfile.h>
#include <keymap.h>
#include <kfont.h>
#include <libkmod.h>
#include <libmount/libmount.h>
#include <proc/readproc.h>

typedef struct
{
    char *fonte;
    char *alvo;
    char *tipo;
    char *opcoes;
} ponto_mnt;

// pid do bash
pid_t bpid;

void configura_terminal(void)
{
    struct termios tty;
    struct kfont_context *kfont_ctx;
    struct kbdfile *kbd_ctx;
    struct lk_ctx *lk_ctx;
    const char *opt;
    int fd;

    const char *const kbddir[] = { "/usr/lib/kbd/keymaps/xkb/", NULL };
    const char *const kbdsuf[] = { ".map", NULL };

    setenv("LC_ALL", "C.UTF-8", 1);
    setlocale(LC_ALL, "");

    // processo do bash configurará como terminal controlador depois
    fd = open("/dev/tty1", O_RDWR|O_NOCTTY);
    if (fd < 0)
    {
        perror("open");
        return;
    }

    ioctl(fd, KDSKBMODE, K_UNICODE);
    if (tcgetattr(fd, &tty) == 0)
    {
        tty.c_iflag |= IUTF8;
        tcsetattr(fd, TCSAFLUSH, &tty);
    }

    kfont_init(NULL, &kfont_ctx);
    if (kfont_ctx != NULL)
    {
        // apenas fontes 8x16 funcionam sem drivers DRM
        kfont_load_font(kfont_ctx, fd, "ter-116b", 0, 0, 0, 0);
        kfont_free(kfont_ctx);
    }

    // kernel cria variável foo=bar para cada opção de boot contendo atribuição
    // sem atribuição, passa a ser argumento do init
    opt = getenv("KEYB");
    if (opt != NULL)
    {
        kbd_ctx = kbdfile_new(NULL);
        if (kbd_ctx != NULL && kbdfile_find(opt, kbddir, kbdsuf, kbd_ctx) == 0)
        {
            lk_ctx = lk_init();
            if (lk_ctx != NULL)
            {
                lk_set_parser_flags(lk_ctx, LK_FLAG_PREFER_UNICODE);
                if (lk_parse_keymap(lk_ctx, kbd_ctx) == 0)
                {
                    lk_load_keymap(lk_ctx, fd, K_UNICODE);
                }

                lk_free(lk_ctx);
            }

            kbdfile_free(kbd_ctx);
        }

        unsetenv("KEYB");
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2)
    {
        close(fd);
    }
}

// sem o ntfs-3g, esta função pode ser substituída por kill(-1, SIGKILL)
void mata_processos(void)
{
    PROCTAB *proc;
    proc_t *info;

    proc = openproc(PROC_FILLSTAT);
    if (proc != NULL)
    {
        while ((info = readproc(proc, NULL)) != NULL)
        {
            // com ppid 0: init/kthreadd
            // com ppid 2: processos do kernel
            if (info->ppid != 0 &&
                info->ppid != 2 &&
                strcmp(info->cmd, "mount.ntfs") != 0 &&
                strcmp(info->cmd, "mount.ntfs-3g") != 0 &&
                strcmp(info->cmd, "ntfs-3g") != 0)
            {
                // desnecessário verificar se é defunto: kill() retorna 0 igual
                if (kill(info->tid, SIGKILL) == 0)
                {
                    while (waitpid(info->tid, NULL, 0) < 0)
                    {
                        continue;
                    }
                }
            }

            freeproc(info);
        }

        closeproc(proc);
    }
}

void ctrlaltdel(int sn, siginfo_t *si, void *data)
{
    if (sn == SIGINT && si->si_code == SI_KERNEL && bpid > 1)
    {
        // bash ignora SIGTERM
        kill(bpid, SIGHUP);
    }
}

int monta(struct libmnt_context *cxt, ponto_mnt pm)
{
    int r;

    mnt_context_set_source(cxt, pm.fonte);
    mnt_context_set_target(cxt, pm.alvo);
    mnt_context_set_options(cxt, pm.opcoes);
    mnt_context_set_fstype(cxt, pm.tipo);
    mnt_context_append_options(cxt, "X-mount.mkdir");

    // se mnt_context_mount() != 0 já falhou e mnt_context_get_status() de nada serve
    // se mnt_context_mount() == 0 ainda é necessário mnt_context_get_status() == 1
    r = mnt_context_mount(cxt) || !mnt_context_get_status(cxt);
    if (r != 0)
    {
        fprintf(stderr, ANSI_BOLD_RED "nao foi possivel montar %s em %s" ANSI_RESET "\n",
                pm.fonte, pm.alvo);
    }

    mnt_reset_context(cxt);
    return r;
}

unsigned int desmonta_tudo(struct libmnt_context *cxt)
{
    struct libmnt_table *tab;
    struct libmnt_iter *itr;
    struct libmnt_fs *fs;
    const char *mntdir;
    unsigned int err = 0;
    int r;

    tab = mnt_new_table();
    if (tab == NULL)
    {
        return 1;
    }

    if (mnt_table_parse_mtab(tab, NULL) == 0)
    {
        // MNT_ITER_BACKWARD para tentar desmontar um ponto montado dentro do outro
        // não é a forma mais robusta, porém do contrário teria que ser uma função
        // recursiva usando mnt_table_next_child_fs(), o que complicaria demais para
        // o propósito deste código
        itr = mnt_new_iter(MNT_ITER_BACKWARD);

        while (mnt_table_next_fs(tab, itr, &fs) == 0)
        {
            if (mnt_fs_is_pseudofs(fs) != 0)
            {
                continue;
            }

            mntdir = mnt_fs_get_target(fs);
            if (mntdir != NULL && mnt_context_set_target(cxt, mntdir) == 0)
            {
                fprintf(stderr, ANSI_BOLD_CYAN "desmontando %s... " ANSI_RESET, mntdir);
                r = mnt_context_umount(cxt) || !mnt_context_get_status(cxt);
                if (r == 0)
                {
                    fprintf(stderr, ANSI_BOLD_GREEN "sucesso" ANSI_RESET "\n");
                }
                else
                {
                    err++;
                    fprintf(stderr, ANSI_BOLD_RED "falha" ANSI_RESET "\n");
                }

                mnt_reset_context(cxt);
            }
        }

        mnt_free_iter(itr);
        mnt_unref_fs(fs);
    }

    mnt_unref_table(tab);

    return err;
}

void carrega_mod(char *arquivo)
{
    struct kmod_ctx *ctx;
    struct kmod_module *mod;
    int r;

    ctx = kmod_new(NULL, NULL);
    if (ctx == NULL)
    {
        return;
    }

    r = kmod_module_new_from_path(ctx, arquivo, &mod);
    if (r == 0)
    {
        fprintf(stderr, ANSI_BOLD_CYAN "carregando módulo %-16s... " ANSI_RESET, kmod_module_get_name(mod));
        // sem KMOD_PROBE_IGNORE_LOADED, ignora módulos já carregados (ou sendo carregados)
        // sem KMOD_PROBE_FAIL_ON_LOADED, retorna 0 nesse caso
        r = kmod_module_probe_insert_module(mod, 0, NULL, NULL, NULL, NULL);
        if (r == 0)
        {
            fprintf(stderr, ANSI_BOLD_GREEN "sucesso" ANSI_RESET "\n");
        }
        // módulo crc32c_intel retorna -ENODEV em processadores sem SSE4.2 (anteriores aos Nehalem/Bulldozer)
        // não é crítico, pois crc32c_generic (builtin no kernel do Fedora) funciona em qualquer cacareco...
        // geralmente -ENODEV significa hardware sem suporte
        else if (r == -ENODEV)
        {
            fprintf(stderr, ANSI_BOLD_WHITE "sem suporte" ANSI_RESET "\n");
        }
        else
        {
            fprintf(stderr, ANSI_BOLD_RED "falha (%s)" ANSI_RESET "\n", strerror(-r));
        }

        kmod_module_unref(mod);
    }

    kmod_unref(ctx);
}

void lista_dir_mod(char *base)
{
    DIR *pasta;
    struct dirent *ent;
    char *caminho, *ptr;

    pasta = opendir(base);
    if (pasta == NULL)
    {
        perror("opendir");
        return;
    }

    while ((ent = readdir(pasta)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        {
            continue;
        }

        if (asprintf(&caminho, "%s/%s", base, ent->d_name) < 0)
        {
            perror("asprintf");
            continue;
        }

        // tmpfs suporta d_type
        if (ent->d_type == DT_DIR)
        {
            // recursivo
            lista_dir_mod(caminho);
        }
        else if (ent->d_type == DT_REG)
        {
            ptr = strstr(ent->d_name, ".ko");
            if (ptr != NULL && (ptr[3] == '\0' || ptr[3] == '.'))
            {
                carrega_mod(caminho);
            }
        }

        free(caminho);
    }

    closedir(pasta);
}

int main(int argc, char **argv)
{
    struct libmnt_context *cxt;
    struct utsname ut;
    struct sigaction acao;
    pid_t wpid;
    int i, fd;
    char *ker;
    ssize_t j;
    size_t c;

    const char *kquieto = "1 4 1 7";

    const ponto_mnt lista[] =
    {
        // fonte       alvo        tipo        opções
        { "proc",     "/proc",    "proc",     "nosuid,noexec,nodev"                },
        { "sysfs",    "/sys",     "sysfs",    "nosuid,noexec,nodev"                },
        { "devtmpfs", "/dev",     "devtmpfs", "nosuid,strictatime,mode=0755"       },
        { "tmpfs",    "/run",     "tmpfs",    "nosuid,nodev,strictatime,mode=0755" },
    };

    const ponto_mnt efi[] =
    {
        // fonte       alvo                         tipo        opções
        { "efivarfs", "/sys/firmware/efi/efivars", "efivarfs", "nosuid,noexec,nodev" },
    };

    const char *dev_links[][2] =
    {
        // alvo               link
        { "/proc/self/fd",   "/dev/fd" },
        { "/proc/self/fd/0", "/dev/stdin" },
        { "/proc/self/fd/1", "/dev/stdout" },
        { "/proc/self/fd/2", "/dev/stderr" },
        { NULL, NULL },
    };

    if (getpid() != 1)
    {
        return 1;
    }

    sigemptyset(&acao.sa_mask);
    // SA_RESTART evita funções retornando erro (EINTR)
    acao.sa_flags = SA_SIGINFO|SA_RESTART;
    acao.sa_sigaction = ctrlaltdel;
    if (reboot(RB_DISABLE_CAD) == 0)
    {
        sigaction(SIGINT, &acao, NULL);
    }

    umask(0022);

    mnt_init_debug(0);
    cxt = mnt_new_context();
    if (cxt == NULL)
    {
        return 1;
    }
    mnt_context_disable_helpers(cxt, 1);

    printf("\n");
    fflush(stdout);

    for (i = 0; i < sizeof(lista)/sizeof(lista[0]); i++)
    {
        if (monta(cxt, lista[i]) != 0)
        {
            return 1;
        }
    }

    if (access("/sys/firmware/efi/", F_OK) == 0)
    {
        monta(cxt, efi[0]);
    }

    for (i = 0; dev_links[i][0] != NULL; i++)
    {
        if (symlink(dev_links[i][0], dev_links[i][1]) < 0)
        {
            perror("symlink");
        }
    }

    fd = open("/proc/sys/kernel/printk", O_WRONLY);
    if (fd >= 0)
    {
        c = strlen(kquieto);
        while (c != 0)
        {
            j = write(fd, kquieto, c);
            if (j > 0)
            {
                c -= j;
                if (c != 0)
                {
                    kquieto += j;
                }
            }
            // ignoramos erros (ENOSPC, etc)
        }

        close(fd);
    }

    configura_terminal();
    // agora podemos usar acentos e caracteres especiais \o/

    if (uname(&ut) < 0)
    {
        perror("uname");
        return 1;
    }

    if (asprintf(&ker, "%s/%s", "/usr/lib/modules", ut.release) < 0)
    {
        perror("asprintf");
        return 1;
    }

    lista_dir_mod(ker);
    free(ker);

    printf("\n");
    fflush(stdout);

    bpid = fork();
    if (bpid < 0)
    {
        perror("fork");
        return 1;
    }

    if (bpid == 0)
    {
        struct stat sb;
        char *versao;
        char dtmp[9];

        if (setsid() < 0)
        {
            perror("setsid");
        }

        if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) != 0)
        {
            perror("ioctl TIOCSCTTY");
        }

        if (stat("/etc/zerong-release", &sb) == 0 &&
            strftime(dtmp, sizeof(dtmp), "%Y%m%d", localtime(&sb.st_mtime)) > 0 &&
            asprintf(&versao, "%s %s (%s)", "ZeroNG™", dtmp, ut.release) > 0)
        {
            ;
        }
        else
        {
            versao = strdup("ZeroNG™");
        }

        printf(ANSI_BOLD_YELLOW "─────────────────────────────────────────────" ANSI_RESET "\n");
        printf(ANSI_BOLD_YELLOW "%s" ANSI_RESET "\n", versao);
        printf(ANSI_BOLD_YELLOW "─────────────────────────────────────────────" ANSI_RESET "\n\n");
        printf(ANSI_BOLD_YELLOW "→ Instruções: " ANSI_RESET);
        printf(ANSI_BOLD_MAGENTA "`ajuda`" ANSI_RESET "\n\n");
        fflush(stdout);
        free(versao);

        setenv("PATH", "/usr/bin:/usr/sbin", 1);
        setenv("SHELL", "/bin/bash", 1);
        setenv("CLICOLOR", "1", 1);
        setenv("HOME", "/root", 1);
        setenv("PS1", BASH_PS1, 1);
        chdir("/root");
        execlp("bash", "-bash", NULL);
        perror("execlp");
        exit(1);
    }

    while ((wpid = wait(NULL)) > 0)
    {
        if (wpid == bpid)
        {
            mata_processos();
            break;
        }
    }

    printf("\n");
    fflush(stdout);

    if (desmonta_tudo(cxt) != 0)
    {
        sync();
    }

    mnt_free_context(cxt);
    sleep(1);

    if (access("/run/zerong-poweroff", F_OK) == 0)
    {
        reboot(RB_POWER_OFF);
    }
    else
    {
        reboot(RB_AUTOBOOT);
    }

    return 1;
}
