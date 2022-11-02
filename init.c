#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <cpuid.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/kd.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
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
int virt;
int desliga;

int eh_vm(void)
{
    unsigned int eax, ebx, ecx, edx;

    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0)
    {
        return 1;
    }

    // Hypervisor Present Bit: bit 31 do registrador ECX
    return (ecx & (1U << 31)) ? 1 : 0;
}

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
    if (opt == NULL)
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
    unsigned int i = 0, nfd = 0;
    unsigned long evbit[NBITS(EV_MAX)] = { 0 };
    unsigned long keybit[NBITS(KEY_MAX)] = { 0 };
    struct pollfd *pfd = NULL;
    struct input_event ev;
    char *dev_ev;

    for (;;)
    {
        if (asprintf(&dev_ev, "/dev/input/event%u", i) < 0)
        {
            perror("asprintf");
            continue;
        }
        i++;

        fd = open(dev_ev, O_RDONLY);
        free(dev_ev);
        if (fd < 0)
        {
            if (nfd == 0)
            {
                return;
            }

            break;
        }

        if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), evbit) >= 0 &&
            test_bit(EV_KEY, evbit) &&
            ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit) >= 0 &&
            test_bit(KEY_POWER, keybit) &&
            (pfd = realloc(pfd, sizeof(*pfd) * (nfd + 1))) != NULL)
        {
            pfd[nfd].fd = fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            nfd++;
        }
        else
        {
            close(fd);
        }
    }

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
                // dispositivo desconectado ou erro: não monitorar mais
                close(pfd[i].fd);
                nfd--;
                for (; i < nfd; i++)
                {
                    pfd[i].fd = pfd[i + 1].fd;
                }

                // poll() novamente
                break;
            }

            if (pfd[i].revents & POLLIN)
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

    while (nfd--)
    {
        close(pfd[nfd].fd);
    }

    free(pfd);

    kill(getppid(), SIGTERM);
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

void carrega_mod(char *arquivo)
{
    // em hardware não virtualizado, pulamos estes módulos
    const char *vm_mod[] =
    {
        "hyperv_drm",
        "hyperv_keyboard",
        "hv_storvsc",
        "hv_vmbus",
        "qxl",
        "vmwgfx",
        "scsi_transport_fc", // dependência de hv_storvsc
    };
    const char *nome;
    struct kmod_ctx *ctx;
    struct kmod_module *mod;
    int r, i, pula = 0;

    ctx = kmod_new(NULL, NULL);
    if (ctx == NULL)
    {
        return;
    }

    r = kmod_module_new_from_path(ctx, arquivo, &mod);
    if (r == 0)
    {
        nome = kmod_module_get_name(mod);

        if (virt == 0)
        {
            for (i = 0; i < ARRAYSIZE(vm_mod); i++)
            {
                if (strcmp(vm_mod[i], nome) == 0)
                {
                    pula = 1;
                    break;
                }
            }
        }

        if (pula == 0)
        {
            fprintf(stderr, ANSI_BOLD_CYAN "carregando modulo %-19s... " ANSI_RESET, nome);
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
                fprintf(stderr, ANSI_BOLD_WHITE "sem sup" ANSI_RESET "\n");
            }
            else
            {
                fprintf(stderr, ANSI_BOLD_RED "falha (%s)" ANSI_RESET "\n", strerror(-r));
            }
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

    virt = eh_vm();
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

    if (uname(&ut) != 0)
    {
        perror("uname");
        return 1;
    }

    if (asprintf(&ker, "/usr/lib/modules/%s", ut.release) < 0)
    {
        perror("asprintf");
        return 1;
    }

    lista_dir_mod(ker);
    free(ker);

    configura_terminal();
    // agora podemos usar acentos e caracteres especiais \o/

    if (fork() == 0)
    {
        prctl(PR_SET_NAME, "acpid");
        monitora_evdev();
        exit(0);
    }

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

        if (setsid() < 0)
        {
            perror("setsid");
        }

        if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) != 0)
        {
            perror("ioctl TIOCSCTTY");
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
