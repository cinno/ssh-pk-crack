#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define MAX_PWD_LEN 16

static int nr_cpus = 0;
static char *pk_path = NULL;
static char *output_path = NULL;

void sig_handler(int sig)
{
	if (sig == SIGUSR1)
		exit(0);
}

void show_result(EVP_PKEY *pk, char *pw)
{
	FILE *fp;

	if (output_path) {
		fp = fopen(output_path, "w");
		if (!fp) {
			fprintf(stderr, "[-] Unable to open output file %s\n", output_path);
			fprintf(stderr, "[*] Using stdout as output\n");
			fp = stdout;
		}
	} else {
		fp = stdout;
	}

	fprintf(fp, "\n**********************************************************\n");
	fprintf(fp, "*\tPassphrase match: <%s>\n", pw);
	fprintf(fp, "**********************************************************\n");
	if (pk->type == EVP_PKEY_RSA) {
		fprintf(fp, "\tKey type: PKEY_RSA\n");
		RSA_print_fp(fp, EVP_PKEY_get1_RSA(pk), 8);
	} else if (pk->type == EVP_PKEY_DSA) {
		fprintf(fp, "\tKey type: PKEY_DSA\n");
		DSA_print_fp(fp, EVP_PKEY_get1_DSA(pk), 8);
	} else if (pk->type == EVP_PKEY_EC) {
		fprintf(fp, "\tKey type: PKEY_EC\n");
		EC_KEY_print_fp(fp, EVP_PKEY_get1_EC_KEY(pk), 8);
	} else {
		fprintf(fp, "PEM_read_PrivateKey: mismatch or unknown EVP_PKEY save_type %d", pk->save_type);
	}
	fprintf(fp, "\n");

	if (fp != stdout)
		fclose(fp);
}

void read_stdin_dispatch(int *pipes, int nr_pipes)
{
	int i, ret, curr = 0;
	char pw[MAX_PWD_LEN + 1];
	FILE *fps[nr_pipes];

	signal(SIGUSR1, sig_handler);

	for (i = 0; i < nr_pipes; i++) {
		fps[i] = fdopen(pipes[i], "w");
		if (!fps[i])
			exit(1);
	}

	while (fgets(pw, sizeof(pw) + 1, stdin)) {
		ret = fputs(pw, fps[curr]);
		if (ret == EOF)
			goto out;
		curr = (curr + 1) % nr_pipes;
	}
out:
	for (i = 0; i < nr_pipes; i++)
		fclose(fps[i]);

	exit(0);
}

void crack_ssh_key(const char *path, int rfd)
{
	int i;
	EVP_PKEY *pk;
	char pw[MAX_PWD_LEN];
	FILE *fp_rfd, *fp_key;

	fp_key = fopen(path, "r");
	if (!fp_key) {
		fprintf(stderr, "[-] Unable to open %s\n", path);
		exit(1);
	}

	signal(SIGUSR1, sig_handler);
	fp_rfd = fdopen(rfd, "r");
	if (!fp_rfd)
		exit(1);

	while (fgets(pw, sizeof(pw), fp_rfd)) {
		for (i = 0; i < (sizeof(pw) - 1) && pw[i] != '\n' && pw[i] != '\r'; i++);
		pw[i] = 0;

		pk = PEM_read_PrivateKey(fp_key, NULL, NULL, pw);
		if (pk) {
			show_result(pk, pw);
			EVP_PKEY_free(pk);
			goto out;
		}

		fseek(fp_key, 0, SEEK_SET);
		ERR_clear_error();
	}
out:
	fclose(fp_key);
	fclose(fp_rfd);
	exit(0);
}

void usage(int argc, char **argv)
{
	if (!argc)
		return;

	printf("Usage: %s [-n <value>] [-o <path>] <private_key>\n", argv[0]);
	printf("\t\t-n <value>\tNumber of process to spawn\n");
	printf("\t\t-o <path>\tOutput file to store result\n");
	printf("Example: john -stdout -incremental | %s id_rsa\n", argv[0]);
}

void parse_args(int argc, char **argv)
{
	int opt;

	if (argc < 2) {
		usage(argc, argv);
		exit(1);
	}

	for (;;) {
		opt = getopt(argc, argv, "n:o:");
		if (opt == -1)
			break;

		switch (opt) {
		case 'n':
			nr_cpus = atoi(optarg);
			break;
		case 'o':
			output_path = optarg;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (optind >= argc) {
		usage(argc, argv);
		exit(1);
	}
	pk_path = argv[optind];
}

int main(int argc, char **argv)
{
	int i;
	FILE *fp_key;

	parse_args(argc, argv);

	fp_key = fopen(pk_path, "r");
	if (!fp_key) {
		fprintf(stderr, "[-] Unable to open %s\n", pk_path);
		exit(1);
	}

	SSL_library_init();

	if (PEM_read_PrivateKey(fp_key, NULL, NULL, "")) {
		fprintf(stderr, "[*] No passphrase for key %s\n", pk_path);
		return 0;
	}
	fclose(fp_key);

	if (!nr_cpus) {
		nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
		if (nr_cpus < 0) {
			fprintf(stderr, "[-] Can't get the number of cpus, specify it manually\n");
			usage(argc, argv);
			exit(1);
		}
	}
	fprintf(stderr, "[*] Spawning %d process(es)\n", nr_cpus);

	pid_t pids[nr_cpus];
	int wfds[nr_cpus];
	for (i = 0; i < nr_cpus; i++) {
		int fds[2];
		if (pipe(fds) < 0) {
			perror("pipe");
			exit(1);
		}

		pids[i] = fork();
		switch (pids[i]) {
		case 0:
			close(fds[1]);
			crack_ssh_key(pk_path, fds[0]);
			break;
		case -1:
			perror("fork");
			exit(1);
		default:
			wfds[i] = fds[1];
			close(fds[0]);
		}
	}

	read_stdin_dispatch(wfds, nr_cpus);

	pid_t winner = wait(NULL);

	for (i = 0; i < nr_cpus; i++) {
		if (pids[i] == winner)
			continue;

		kill(pids[i], SIGUSR1);
		waitpid(pids[i], NULL, 0);
		close(wfds[i]);
	}

	return 0;
}
