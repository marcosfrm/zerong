#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/kd.h>
#include <linux/netlink.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/socket.h>
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
#include <libudev.h>

#define ANSI_BOLD_WHITE   "\033[1;37m"
#define ANSI_BOLD_CYAN    "\033[1;36m"
#define ANSI_BOLD_MAGENTA "\033[1;35m"
#define ANSI_BOLD_YELLOW  "\033[1;33m"
#define ANSI_BOLD_GREEN   "\033[1;32m"
#define ANSI_BOLD_RED     "\033[1;31m"
#define ANSI_RESET        "\033[0m"

// ANSI_BOLD_YELLOW
#define BASH_PS1 "\\[\\033[1;33m\\]\\$\\[\\033[0m\\] "

#define ARRAYSIZE(x)            (sizeof(x)/sizeof((x)[0]))
// ferramental para evdev
#define BITS_PER_LONG           (sizeof(unsigned long) * 8)
#define NBITS(x)                ((((x)-1)/BITS_PER_LONG)+1)
#define EVDEV_OFF(x)            ((x)%BITS_PER_LONG)
#define EVDEV_LONG(x)           ((x)/BITS_PER_LONG)
#define test_bit(bit, array)    ((array[EVDEV_LONG(bit)] >> EVDEV_OFF(bit)) & 1)

typedef struct
{
    char *fonte;
    char *alvo;
    char *tipo;
    char *opcoes;
} ponto_mnt;

pid_t bpid;
int desliga, pipefd[2];

// intervalo máximo: 0-9
void cor_ansi(int min, int max, char *buf, size_t buflen)
{
    unsigned int cor;

    cor = min + rand() / (RAND_MAX / (max - min + 1) + 1);
    snprintf(buf, buflen, "\033[1;3%um", cor);
}

void saudacao(void)
{
    time_t agora;
    struct tm *tm;
    const char *msg;
    char ecode[11];
    size_t len;
    int i, res, pad;

    agora = time(NULL);
    // máquinas com Windows são mais populares, por isso gmtime() ao invés de localtime(),
    // caso o RTC esteja em UTC, o horário estará adiantado 3h... paciência :(
    tm = gmtime(&agora);
    srand(agora);

    if (tm->tm_hour >= 0 && tm->tm_hour < 6)
    {
        msg = "Boa madrugada!";
    }
    else if (tm->tm_hour >= 6 && tm->tm_hour < 12)
    {
        msg = "Bom dia!";
    }
    else if (tm->tm_hour >= 12 && tm->tm_hour < 18)
    {
        msg = "Boa tarde!";
    }
    else
    {
        msg = "Boa noite!";
    }

    // não há caracteres especiais na string, senão teria que usar wchar_t e tralha relacionada
    len = strlen(msg) + 2; // dois espaços
    // 48 colunas
    res = (48 - len) % 2;
    pad = (48 - len) / 2;

    for (i = 0; i < pad; i++)
    {
        cor_ansi(1, 7, ecode, sizeof(ecode));
        printf("%s~", ecode);
    }

    printf(ANSI_BOLD_YELLOW " %s ", msg);

    for (i = 0; i < (pad + res); i++)
    {
        cor_ansi(1, 7, ecode, sizeof(ecode));
        printf("%s~", ecode);
    }

    printf(ANSI_RESET "\n\n");
}

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
    fd = open("/dev/tty0", O_RDWR|O_NOCTTY);
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
        // requer driver DRM
        kfont_load_font(kfont_ctx, fd, "ter-120b", 0, 0, 0, 0);
        kfont_free(kfont_ctx);
    }

    // kernel cria variável foo=bar para cada opção de boot contendo atribuição
    // sem atribuição, passa a ser argumento do init
    opt = getenv("KEYB");
    if (opt == NULL || opt[0] == '\0')
    {
        opt = "br";
    }

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

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
    {
        close(fd);
    }
}

void termina_bash(int sinal)
{
    if (bpid > 1)
    {
        switch (sinal)
        {
            case SIGTERM:
                desliga = 1;
                // fallthrough
            case SIGINT:
                // bash ignora SIGTERM
                kill(bpid, SIGHUP);
            default:
                break;
        }
    }
}


// função inspirada em:
// https://github.com/mirror/busybox/blob/1_35_0/util-linux/acpid.c
// com a restrição de dispositivos de:
// https://github.com/libsdl-org/SDL/blob/release-2.0.22/src/core/linux/SDL_evdev_capabilities.h
// https://github.com/libsdl-org/SDL/blob/release-2.0.22/src/joystick/linux/SDL_sysjoystick.c
void monitora_evdev(void)
{
    int fd, pronto = 0;
    unsigned int i, j, nfd = 0;
    unsigned long evbit[NBITS(EV_MAX)] = { 0 };
    unsigned long keybit[NBITS(KEY_MAX)] = { 0 };
    struct pollfd *pfd, *tmp;
    struct input_event ev;
    char buf[1024], dev_ev[64];
    char *ptr;
    ssize_t n;

    // fechar escrita
    close(pipefd[1]);

    pfd = malloc(sizeof(*pfd));
    if (pfd == NULL)
    {
        perror("malloc");
        return;
    }

    pfd[nfd].fd = pipefd[0];
    pfd[nfd].events = POLLIN;
    pfd[nfd].revents = 0;
    nfd++;

    while (pronto == 0)
    {
        if (poll(pfd, nfd, -1) < 0)
        {
            perror("poll");
            continue;
        }

        for (i = 0; i < nfd; i++)
        {
            if (pfd[i].revents & (POLLHUP|POLLERR))
            {
                if (i == 0)
                {
                    // problema no pipe, fatal
                    pronto = 2;
                }
                else
                {
                    // dispositivo desconectado ou erro: não monitorar mais
                    close(pfd[i].fd);
                    nfd--;
                    for (j = i; j < nfd; j++)
                    {
                        pfd[j] = pfd[j + 1];
                    }

                    // poll() novamente
                }

                break;
            }

            if (pfd[i].revents & POLLIN)
            {
                if (i == 0)
                {
                    n = read(pfd[i].fd, buf, sizeof(buf));
                    if (n > 0)
                    {
                        ptr = buf;

                        while (ptr < buf + n)
                        {
                            snprintf(dev_ev, sizeof(dev_ev), "/dev/%s", ptr);

                            fd = open(dev_ev, O_RDONLY);
                            if (fd < 0)
                            {
                                perror("open");
                            }
                            else if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), evbit) >= 0 &&
                                     test_bit(EV_KEY, evbit) &&
                                     ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit) >= 0 &&
                                     test_bit(KEY_POWER, keybit))
                            {
                                tmp = realloc(pfd, sizeof(*pfd) * (nfd + 1));
                                if (tmp == NULL)
                                {
                                    perror("realloc");
                                    close(fd);
                                }
                                else
                                {
                                    pfd = tmp;
                                    pfd[nfd].fd = fd;
                                    pfd[nfd].events = POLLIN;
                                    pfd[nfd].revents = 0;
                                    nfd++;

                                    // continua o loop, pois o novo elemento terá revents zerado
                                }
                            }
                            else
                            {
                                close(fd);
                            }

                            ptr += strlen(ptr) + 1;
                        }
                    }
                }
                else
                {
                    if (read(pfd[i].fd, &ev, sizeof(ev)) != sizeof(ev))
                    {
                        continue;
                    }

                    if (ev.type == EV_KEY && ev.value == 1 && ev.code == KEY_POWER)
                    {
                        pronto = 1;
                        break;
                    }
                }
            }

        }
    }

    while (nfd--)
    {
        close(pfd[nfd].fd);
    }

    free(pfd);

    if (pronto == 1)
    {
        kill(getppid(), SIGTERM);
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

void desmonta_tudo(struct libmnt_context *cxt)
{
    struct libmnt_table *tab;
    struct libmnt_iter *itr;
    struct libmnt_fs *fs;
    struct udev *ucxt;
    struct udev_enumerate *ue;
    struct udev_list_entry *dev;
    struct udev_device *blkdev, *usbdev;
    const char *mntdir;
    char *syspath;
    unsigned int err = 0, usbc = 0;
    int fd, r;

    tab = mnt_new_table();
    if (tab == NULL)
    {
        return;
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

    // não tendo nada mais montado, tentamos desconectar portas USB usadas por dispositivos de bloco
    if (err == 0)
    {
        ucxt = udev_new();
        ue = udev_enumerate_new(ucxt);
        udev_enumerate_add_match_subsystem(ue, "block");
        // ignorar partições
        udev_enumerate_add_match_property(ue, "DEVTYPE", "disk");
        udev_enumerate_scan_devices(ue);

        udev_list_entry_foreach(dev, udev_enumerate_get_list_entry(ue))
        {
            blkdev = udev_device_new_from_syspath(ucxt, udev_list_entry_get_name(dev));
            if (blkdev != NULL)
            {
                usbdev = udev_device_get_parent_with_subsystem_devtype(blkdev, "usb", "usb_device");
                if (usbdev != NULL)
                {
                    // https://github.com/torvalds/linux/commit/253e05724f9230910344357b1142ad8642ff9f5a
                    if (asprintf(&syspath, "%s/remove", udev_device_get_syspath(usbdev)) > 0)
                    {
                        fd = open(syspath, O_WRONLY);
                        if (fd >= 0)
                        {
                            fprintf(stderr, ANSI_BOLD_CYAN "desconectando porta USB %s (%s)... " ANSI_RESET,
                                    udev_device_get_sysname(usbdev), udev_device_get_devnode(blkdev));
                            if (write(fd, "1", 1) == 1)
                            {
                                usbc++;
                                fprintf(stderr, ANSI_BOLD_GREEN "sucesso" ANSI_RESET "\n");
                            }
                            else
                            {
                                fprintf(stderr, ANSI_BOLD_RED "falha" ANSI_RESET "\n");
                            }

                            close(fd);
                        }

                        free(syspath);
                    }

                    // usbdev é desalocado junto com blkdev
                }

                udev_device_unref(blkdev);
            }
        }

        if (usbc != 0)
        {
            // alguns segundos para discos externos desligarem
            for (r = 0; r < 5; r++)
            {
                fprintf(stderr, ANSI_BOLD_CYAN ". " ANSI_RESET);
                sleep(1);
            }

            fprintf(stderr, "\n");
        }

        udev_enumerate_unref(ue);
        udev_unref(ucxt);
    }
    else
    {
        sync();
    }

    mnt_unref_table(tab);
}

void trigger_coldplug(const char *base)
{
    DIR *dir;
    struct dirent *ent;
    char *caminho;
    int fd;

    dir = opendir(base);
    if (!dir)
    {
        perror("opendir");
        return;
    }

    while ((ent = readdir(dir)) != NULL)
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

        if (ent->d_type == DT_DIR)
        {
            trigger_coldplug(caminho);
        }
        else if (ent->d_type == DT_REG && strcmp(ent->d_name, "uevent") == 0)
        {
            fd = open(caminho, O_WRONLY);
            if (fd >= 0)
            {
                if (write(fd, "add", 3) < 0)
                {
                    perror("write");
                }

                close(fd);
            }
        }

        free(caminho);
    }

    closedir(dir);
}

void device_manager(void)
{
    const char *const no_config[] = { NULL };
    struct kmod_ctx *ctx;
    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = 1, // kernel
    };
    int fd;
    const int sock_sz = 8*1024*1024;
    char buf[4096];
    ssize_t len;

    // fechar leitura
    close(pipefd[0]);

    ctx = kmod_new(NULL, no_config);
    if (ctx == NULL)
    {
        return;
    }

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (fd < 0)
    {
        perror("socket");
        return;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sock_sz, sizeof(sock_sz)) < 0) {
        perror("setsockopt");
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind");
        close(fd);
        return;
    }

    trigger_coldplug("/sys/bus");
    trigger_coldplug("/sys/devices");

    while (1)
    {
        const char *action = NULL;
        const char *devname = NULL;
        const char *devtype = NULL;
        const char *modalias = NULL;
        const char *subsystem = NULL;
        struct kmod_list *l, *list = NULL;
        int r;

        len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0)
        {
            perror("recv");
            continue;
        }

        for (char *p = buf; p - buf < len; p += strlen(p) + 1)
        {
            if (strncmp(p, "ACTION=", 7) == 0)
            {
                action = p + 7;
            }
            else if (strncmp(p, "DEVNAME=", 8) == 0)
            {
                devname = p + 8;
            }
            else if (strncmp(p, "DEVTYPE=", 8) == 0)
            {
                devtype = p + 8;
            }
            else if (strncmp(p, "MODALIAS=", 9) == 0)
            {
                modalias = p + 9;
            }
            else if (strncmp(p, "SUBSYSTEM=", 10) == 0)
            {
                subsystem = p + 10;
            }
        }

        if (action != NULL && (strcmp(action, "add") == 0 || strcmp(action, "bind") == 0) &&
            modalias != NULL)
        {
            r = kmod_module_new_from_lookup(ctx, modalias, &list);
            if (r == 0 && list != NULL)
            {
                kmod_list_foreach(l, list)
                {
                    struct kmod_module *mod = kmod_module_get_module(l);

                    r = kmod_module_probe_insert_module(mod, 0, NULL, NULL, NULL, NULL);
                    if (r < 0)
                    {
                        fprintf(stderr, ANSI_BOLD_RED "falha ao carregar modulo '%s' para modalias '%s' (action '%s'): %s"
                                ANSI_RESET "\n", kmod_module_get_name(mod), modalias, action, strerror(-r));
                    }

                    kmod_module_unref(mod);
                }

                kmod_module_unref_list(list);
            }
        }

        // eventos "change" não são relevantes, pois indicam mudança de estado/atributos de dispositivos
        // com módulos *já carregados*, como hotplug de conectores hdmi, etc
        if (action != NULL && strcmp(action, "add") == 0)
        {
            if (subsystem != NULL && strcmp(subsystem, "drm") == 0 &&
                devtype != NULL && strcmp(devtype, "drm_minor") == 0)
            {
                configura_terminal();
            }

            if (subsystem != NULL && strcmp(subsystem, "input") == 0 &&
                devname != NULL && strncmp(devname, "input/event", 11) == 0)
            {
                // + 1 para \0 ir junto
                if (write(pipefd[1], devname, strlen(devname) + 1) < 0)
                {
                    perror("write");
                }
            }
        }
    }

    kmod_unref(ctx);
    close(pipefd[1]);
    close(fd);
}

int main(int argc, char **argv)
{
    struct libmnt_context *cxt;
    struct sigaction acao;
    pid_t wpid;
    int i, fd;
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
        { "/proc/self/fd",   "/dev/fd"     },
        { "/proc/self/fd/0", "/dev/stdin"  },
        { "/proc/self/fd/1", "/dev/stdout" },
        { "/proc/self/fd/2", "/dev/stderr" },
    };

    if (getpid() != 1)
    {
        return 1;
    }

    sigfillset(&acao.sa_mask);
    // SA_RESTART evita funções retornando erro (EINTR)
    acao.sa_flags = SA_RESTART;
    acao.sa_handler = termina_bash;
    if (reboot(RB_DISABLE_CAD) == 0)
    {
        sigaction(SIGINT, &acao, NULL);
    }
    sigaction(SIGTERM, &acao, NULL);

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

    for (i = 0; i < ARRAYSIZE(lista); i++)
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

    for (i = 0; i < ARRAYSIZE(dev_links); i++)
    {
        if (symlink(dev_links[i][0], dev_links[i][1]) != 0)
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

    if (pipe(pipefd) < 0)
    {
        perror("pipe");
        return 1;
    }

    if (fork() == 0)
    {
        setsid();
        prctl(PR_SET_NAME, "acpid");
        monitora_evdev();
        exit(0);
    }

    if (fork() == 0)
    {
        setsid();
        prctl(PR_SET_NAME, "devmgr");
        device_manager();
        exit(0);
    }

    close(pipefd[0]);
    close(pipefd[1]);

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
        FILE *fp;
        char *versao;
        char dtmp[9];
        struct utsname ut;

        if (setsid() < 0)
        {
            perror("setsid");
        }

        if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) != 0)
        {
            perror("ioctl TIOCSCTTY");
        }

        if (uname(&ut) != 0)
        {
            perror("uname");
        }

        if ((fp = fopen("/etc/zerong-release", "r")) != NULL &&
            fgets(dtmp, sizeof(dtmp), fp) != NULL &&
            fclose(fp) == 0 &&
            asprintf(&versao, "ZeroNG™ %s (%s)", dtmp, ut.release) > 0)
        {
            ;
        }
        else
        {
            versao = strdup("ZeroNG™");
        }

        saudacao();

        printf(ANSI_BOLD_YELLOW "────────────────────────────────────────────────" ANSI_RESET "\n");
        printf(ANSI_BOLD_YELLOW "%s" ANSI_RESET "\n", versao);
        printf(ANSI_BOLD_YELLOW "────────────────────────────────────────────────" ANSI_RESET "\n\n");
        printf(ANSI_BOLD_YELLOW "→ Instruções: " ANSI_RESET);
        printf(ANSI_BOLD_MAGENTA "`ajuda`" ANSI_RESET "\n\n");
        fflush(stdout);
        free(versao);

        setenv("PATH", "/usr/bin:/usr/sbin", 1);
        setenv("SHELL", "/bin/bash", 1);
        setenv("EDITOR", "nano", 1);
        setenv("CLICOLOR", "1", 1);
        setenv("HOME", "/root", 1);
        setenv("PS1", BASH_PS1, 1);
        if (chdir("/root") != 0)
        {
            perror("chdir");
        }
        execlp("bash", "-bash", NULL);
        perror("execlp");
        exit(1);
    }

    while ((wpid = wait(NULL)) > 0)
    {
        if (wpid == bpid)
        {
            kill(-1, SIGKILL);
        }
    }

    printf("\n");
    fflush(stdout);

    desmonta_tudo(cxt);
    mnt_free_context(cxt);
    sleep(1);

    if (desliga == 1)
    {
        reboot(RB_POWER_OFF);
    }
    else
    {
        reboot(RB_AUTOBOOT);
    }

    return 1;
}
