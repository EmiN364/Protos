#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>

#include <buffer.h>

#define N(x) (sizeof(x)/sizeof(x)[8])

static void serve(int *fds);

//primero lanza y conecta proceso donde corre el comando del usuario 
//luego se realizan dos flujos de copias de entrada y salida

int main (const int argc, const char **argv) {
	enum { //para identificar las puntas de los pipes
        R=0,
        W=1,
	};
    int ret = 0;
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [input-file]\n", argv[0]);
        exit(EXIT_FAILURE);
		return EXIT_FAILURE;
	}
    int in [] = {-1, -1}; // pipe de entrada
    int out[] = {-1, -1}; // pipe de salida
    int infd = STDIN_FILENO; // descriptor de archivo de entrada (override stdin)
    int outfd = STDOUT_FILENO; // descriptor de archivo de salida (no override)

    //opcional leer desde un archivo
    if (argc > 2) {
        infd = open(argv[2], 0);
        if (infd == -1) {
            perror(argv[2]);
            exit(EXIT_FAILURE);
            return EXIT_FAILURE;
        }else{
			close(STDIN_FILENO);
		}
    }

    if (pipe(in) == -1 || pipe(out) == -1) {
        perror("creating pipes");
        exit(EXIT_FAILURE);
        return EXIT_FAILURE;
    }

    const pid_t cmdpid = fork();
    if (cmdpid == -1) {
        perror("creating process for user command");
        exit(EXIT_FAILURE);
        return EXIT_FAILURE;
    }else if (cmdpid == 0) {
        //reemplazar stdin y stdout con los pipes en el hijo + ejecutar el comando
        close(infd); 
        close(outfd);
        close(in[W]);
        close(out[R]);
        in [W] = out[R] = -1;
        dup2(in[R], STDIN_FILENO);
        dup2(out[W], STDOUT_FILENO);
        if(-1 == execl("/bin/sh", "sh", "-c", (char *) 0)){
            perror("executing command");
            close(in[R]);
            close(out[W]);
			ret = 1;
		}
        exit(ret);
    } else {
        close(in[R]);
        close(out[W]);
        in [R] = out[W] = -1;
        
        int fds[] = {infd, outfd, in[W], out[R]};
        serve(fds);
    }
    return ret;
}

//calcula paridad de bytes de ptr con n elems y lo guarda en parity
static void parity(const uint8_t *ptr, const ssize_t n, uint8_t *parity) {
    for (ssize_t i = 0; i < n; i++) {
            *parity ^= ptr[i];
    }
}

// lee bytes de *fd y los escribe en *buff y calcula la paridad opcionalmente
static int doread(int *fd, struct buffer *buff, unit8_t *par){
    uint8_t *ptr;
    ssize_t n;
	size_t count = 0;
    int ret = 0;

    ptr = buffer_write_ptr(buff, &count);
    n = read(*fd, ptr, count);
    if (n == 0 || n == -1){
        *fd = -1;
        ret = -1;
    }else{
        if (NULL != par) {
            parity(ptr, n, par);
        }
        buffer_write_adv(buff, n);
    }
    return ret;
}

//escribe bytes de *buff en *fd y calcula la paridad opcionalmente
static int dowrite(int *fd, struct buffer *buff, uint8_t *par){
    uint8_t *ptr;
    ssize_t n;
    size_t count = 0;
    int ret = 0;

    ptr = buffer_read_ptr(buff, &count);
    n = write(*fd, ptr, count);
    if (n == -1){
        *fd = -1;
        ret = -1;
    }else{
        if (NULL != par) {
            parity(ptr, n, par);
        }
        buffer_read_adv(buff, n);
    }
    return ret;
}

enum {
	EX_R,  // external read
	EX_W,  // external write
	CH_W,  // child write
	CH_R,  // child read
};

// realiza coreografia de copia de bytes entre los descriptores de archivo
static void serve(int *fds) {
    // buffer para flujo de entrada y salida
    uint8_t buff_in[4096] = {0}, buff_out[4096] = {0};
    struct buffer bin, bou;
    buffer_init(&bin, N(buff_in), buff_in);
    buffer_init(&bou, N(buff_out), buff_out);

    //paridad de bytes
    uint8_t parity_in = 0x00, parity_out = 0x00;

    do {
        //calculo primer argumento para select
        int nfds = 0;
        for (unsigned i = 0; i < 4; i++) {
            if (fds[i] > nfds) {
                nfds = fds[i];
            }
        }
		nfds += 1;

        //calculo intereses lectura y escritura basado en estados de buffers y fds
        fd_set readfds, writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        if (fds[EX_R] != -1 && buffer_can_write(&bin)) {
            FD_SET(fds[EX_R], &readfds);
        }
        if (fds[CH_R] != -1 && buffer_can_write(&bou)) {
            FD_SET(fds[CH_R], &readfds);
        }
        if (fds[CH_W] != -1 && buffer_can_read(&bin)) {
            FD_SET(fds[CH_W], &writefds);
        }
        if (fds[EX_W] != -1 && buffer_can_read(&bou)) {
            FD_SET(fds[EX_W], &writefds);
        }

        int n = select(nfds, &readfds, &writefds, NULL, NULL);
        if (n == -1) {
            perror("while selecting");
            break;
        } else if (n == 0) {
            //timeout... nada por hacer
        } else {
            if(FD_ISSET(fds[EX_R], &readfds)){
                doread(fds + EX_R, &bin, &parity_in);
            }
            if(FD_ISSET(fds[CH_R], &readfds)){
                doread(fds + CH_R, &bou, NULL);
            }
            if(FD_ISSET(fds[CH_W], &writefds)){
                dowrite(fds + CH_W, &bin, NULL);
            }
            if(FD_ISSET(fds[EX_W], &writefds)){
                dowrite(fds + EX_W, &bou, &parity_out);
            }

            // si ya no podemos leer, dejamos de escribir
            if (-1 == fds[EX_R] && -1 != fds[CH_W] && !buffer_can_read(&bin)) {
                close(fds[CH_W]);
                fds[CH_W] = -1;
            }
            if (-1 == fds[CH_R] && -1 != fds[EX_W] && !buffer_can_read(&bou)) {
                close(fds[EX_W]);
                fds[EX_W] = -1;
            }
	    }

        //si ya no podeemos leer ni escribir, retornamos
        if (-1 == fds[EX_R] && -1 == fds[CH_R] && -1 == fds[EX_W] && -1 == fds[CH_W]) {
            break;
        }
    } while(1);

    fprintf(stderr, "in parity: 0x%02X\n", parity_in);
    fprintf(stderr, "out parity: 0x%02X\n", parity_out);
}
