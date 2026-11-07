/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Host integration test (root, build host) for the client /proc isolation of
 * tee-t3-run.c: runs the runner's own client_pidns() (own pid namespace, pid 1
 * reaper, fresh procfs with hidepid=invisible, client as pid 2 with uid 1000,
 * NO_NEW_PRIVS and a seccomp filter) with this binary as the "client".
 *
 * A same-uid process outside the namespace (sleeper, uid 1000, dumpable) is
 * the target of the review's /proc/<pid>/root alias:
 *   control: a uid 1000 process WITHOUT the isolation can open
 *            /proc/<sleeper>/root (proves the alias exists on this host);
 *   probe:   the isolated client sees only its own pid (2), no /proc/1, no
 *            /proc/<sleeper>, one proc mount (hidepid=invisible), and
 *            /proc/self still works (bionic linker / HAL);
 *   exit:    the client's exit status and a default-action SIGALRM (alarm(),
 *            as the clients use) propagate through pid 1.
 *
 * Everything runs in a private mount namespace (MS_REC|MS_PRIVATE first;
 * build.sh also wraps it in unshare -m --propagation private), so the /proc
 * replacement never reaches the host. Built and run by build.sh for TEE_T3.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define main t3_runner_main
#include "tee-t3-run.c"
#undef main

static int fails;
#define EXPECT(cond, ...) do { if (!(cond)) { fails++; printf("FAIL " __VA_ARGS__); } } while (0)

/* ---------------------------------------------------------- client side */
static int probe(const char *sleeper)
{
	char path[64], buf[4096];
	struct stat sb;
	DIR *d;
	struct dirent *e;
	int pids = 0, foreign = 0, procs = 0, fd;
	ssize_t n;
	FILE *f;
	char *line = NULL;
	size_t cap = 0;

	EXPECT(getpid() == 2, "probe pid %d, want 2\n", (int)getpid());
	EXPECT(getuid() == 1000 && geteuid() == 1000 && getgid() == 1000, "probe ids\n");
	EXPECT(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "probe no_new_privs\n");
	d = opendir("/proc");
	EXPECT(d != NULL, "probe opendir /proc errno=%d\n", errno);
	while (d && (e = readdir(d))) {
		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		pids++;
		if (strcmp(e->d_name, "2"))
			foreign++;
	}
	if (d)
		closedir(d);
	EXPECT(pids == 1 && !foreign, "probe sees %d pids (%d foreign)\n", pids, foreign);
	EXPECT(stat("/proc/1", &sb) && errno == ENOENT, "probe /proc/1 visible\n");
	{
		struct stat proc, sysrq;

		EXPECT(!stat("/proc", &proc) && !stat("/proc/sysrq-trigger", &sysrq) &&
		       sysrq.st_dev != proc.st_dev && sysrq.st_size == 0,
		       "probe /proc/sysrq-trigger not masked\n");
	}
	EXPECT(open("/proc/1/root", O_PATH | O_CLOEXEC) < 0 && errno == ENOENT, "probe /proc/1/root\n");
	snprintf(path, sizeof(path), "/proc/%s", sleeper);
	EXPECT(stat(path, &sb) && errno == ENOENT, "probe %s visible\n", path);
	snprintf(path, sizeof(path), "/proc/%s/root", sleeper);
	EXPECT(open(path, O_PATH | O_CLOEXEC) < 0, "probe %s reachable\n", path);
	n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	EXPECT(n > 0, "probe /proc/self/exe errno=%d\n", errno);
	if (n > 0) {
		buf[n] = 0;
		EXPECT(strstr(buf, "t3-pidns-fixture") != NULL, "probe exe %s\n", buf);
	}
	fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
	if (fd >= 0)
		close(fd);
	if (n > 0)
		buf[n] = 0;
	EXPECT(n > 0 && strstr(buf, "\nUid:\t1000\t"), "probe /proc/self/status\n");
	f = fopen("/proc/self/mountinfo", "re");
	EXPECT(f != NULL, "probe mountinfo\n");
	while (f && getline(&line, &cap, f) > 0) {
		const char *sep = strstr(line, " - ");

		if (sep && !strncmp(sep + 3, "proc ", 5)) {
			procs++;
			EXPECT(strstr(sep, "hidepid=invisible") != NULL, "probe proc mount without hidepid\n");
		}
	}
	free(line);
	if (f)
		fclose(f);
	EXPECT(procs == 1, "probe sees %d proc mounts\n", procs);
	printf("T3PF probe pid=%d uid=%d pids_visible=%d proc_mounts=%d failures=%d\n",
	       (int)getpid(), (int)getuid(), pids, procs, fails);
	return fails ? 10 : 0;
}

/* uid 1000 without isolation: the alias the review describes must work here */
static int control(const char *sleeper)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/proc/%s/root", sleeper);
	fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	printf("T3PF control uid=%d %s %s (errno=%d)\n", (int)getuid(), path,
	       fd >= 0 ? "reachable" : "NOT reachable", fd >= 0 ? 0 : errno);
	return fd >= 0 ? 0 : 3;
}

/* --------------------------------------------------------- runner side */
static char self[4096], empty[64];

static pid_t as_system(const char *argv0, const char *arg)
{
	pid_t pid;

	fflush(stdout);
	pid = fork();
	if (pid)
		return pid;
	if (drop_to_system(NULL, 0))
		_exit(120);
	execl(self, argv0, arg, (char *)NULL);
	_exit(127);
}

static int wait_cmdline(pid_t pid, const char *want)
{
	char path[64], buf[256];

	snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
	for (int i = 0; i < 100; i++) {
		int n = read_text(path, buf, sizeof(buf));

		if (n > 0 && !strcmp(buf, want))
			return 0;
		usleep(20000);
	}
	return -1;
}

/* One client_pidns() run in a child (unshare(CLONE_NEWPID) is once per process). */
static int scenario(const char *argv0, const char *arg)
{
	static struct t3_prog allow;
	pid_t pid;

	allow.n = 0;
	ret(&allow, SECCOMP_RET_ALLOW);	/* build host is not aarch64: no arch check */
	fflush(stdout);
	pid = fork();
	if (!pid)
		_exit(client_pidns(self, argv0, arg, &allow, empty));
	return child_status(pid);
}

int main(int argc, char **argv)
{
	char spid[16];
	pid_t sleeper;
	int rc;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!strcmp(argv[0], "t3pf-probe") && argc == 2)
		return probe(argv[1]);
	if (!strcmp(argv[0], "t3pf-control") && argc == 2)
		return control(argv[1]);
	if (!strcmp(argv[0], "t3pf-sleep")) {
		sleep(120);
		return 0;
	}
	if (!strcmp(argv[0], "t3pf-exit7"))
		return 7;
	if (!strcmp(argv[0], "t3pf-alarm")) {
		alarm(1);
		for (;;)
			pause();
	}

	if (getuid() != 0)
		return printf("t3 pidns fixture: FAIL (needs root)\n"), 1;
	if (!realpath("/proc/self/exe", self))
		return printf("t3 pidns fixture: FAIL (realpath)\n"), 1;
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return printf("t3 pidns fixture: FAIL (private mount ns errno=%d)\n", errno), 1;
	/* mask source as the runner's mode-0000 t3-cns/empty */
	{
		char dir[] = "/dev/shm/t3pf-XXXXXX";
		int fd;

		if (!mkdtemp(dir))
			return printf("t3 pidns fixture: FAIL (mkdtemp errno=%d)\n", errno), 1;
		snprintf(empty, sizeof(empty), "%s/empty", dir);
		fd = open(empty, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0000);
		if (fd < 0 || close(fd))
			return printf("t3 pidns fixture: FAIL (empty errno=%d)\n", errno), 1;
	}

	sleeper = as_system("t3pf-sleep", NULL);
	if (sleeper < 0 || wait_cmdline(sleeper, "t3pf-sleep"))
		return printf("t3 pidns fixture: FAIL (sleeper)\n"), 1;
	snprintf(spid, sizeof(spid), "%d", (int)sleeper);

	/* 1. without isolation the same-uid alias exists */
	{
		pid_t c = as_system("t3pf-control", spid);

		rc = c > 0 ? child_status(c) : 125;
		EXPECT(rc == 0, "control: /proc/%s/root not reachable without isolation (rc=%d); "
		       "this host cannot demonstrate the alias\n", spid, rc);
	}
	/* 2. the runner's isolation */
	rc = scenario("t3pf-probe", spid);
	EXPECT(rc == 0, "isolated probe rc=%d\n", rc);
	/* 3. exit status and default-action signals reach the runner */
	rc = scenario("t3pf-exit7", "x");
	EXPECT(rc == 7, "exit status through pid 1: %d, want 7\n", rc);
	rc = scenario("t3pf-alarm", "x");
	EXPECT(rc == 128 + SIGALRM, "alarm() in the client: %d, want %d\n", rc, 128 + SIGALRM);

	kill(sleeper, SIGKILL);
	waitpid(sleeper, NULL, 0);
	unlink(empty);
	*strrchr(empty, '/') = 0;
	rmdir(empty);
	printf("t3 pidns fixture: %s (%d failures; control, isolated probe, exit 7, SIGALRM)\n",
	       fails ? "FAIL" : "PASS", fails);
	return !!fails;
}
