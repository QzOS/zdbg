/*
 * main.c - zdbg entry point.
 *
 * Parses a small set of command-line options, optionally
 * loads a startup file and one or more `-x` script files,
 * then either exits (in --batch mode) or hands control to
 * the interactive REPL.  Remaining argv after `--` or after
 * options is remembered on the zdbg state so that a bare `l`
 * at the prompt launches the target named on the command line.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <io.h>
#  define ZDBG_ISATTY(fd) _isatty(fd)
#  define ZDBG_FILENO(f)  _fileno(f)
#else
#  include <unistd.h>
#  define ZDBG_ISATTY(fd) isatty(fd)
#  define ZDBG_FILENO(f)  fileno(f)
#endif

#include "zdbg.h"
#include "zdbg_cmd.h"
#include "zdbg_stdio.h"

#define ZDBG_MAX_SCRIPT_FILES 16

/* Exit codes (documented in README). */
#define ZDBG_EXIT_OK        0
#define ZDBG_EXIT_CMD_FAIL  1
#define ZDBG_EXIT_SETUP     2

static void
banner(void)
{
	printf("zdbg %d.%d - small DEBUG.COM-inspired debugger\n"
	    "type ? for help, q to quit\n",
	    ZDBG_VERSION_MAJOR, ZDBG_VERSION_MINOR);
}

static void
usage(FILE *fp)
{
	fprintf(fp,
	    "usage: zdbg [options] [target [args...]]\n"
	    "\n"
	    "options:\n"
	    "  -x, --execute PATH   execute commands from script file\n"
	    "                       (may be given multiple times)\n"
	    "  -b, --batch          batch mode: exit after scripts/stdin\n"
	    "  -q, --quiet          suppress banner and prompts\n"
	    "  -v, --verbose        echo script commands before execution\n"
	    "      --no-init        do not load $HOME/.zdbgrc startup file\n"
	    "      --stdin PATH     redirect target stdin from file\n"
	    "      --stdout PATH    redirect target stdout to file\n"
	    "      --stderr PATH    redirect target stderr to file\n"
	    "      --capture-stdout configure file-backed stdout capture\n"
	    "      --capture-stderr configure file-backed stderr capture\n"
	    "      --null-stdin     send EOF on target stdin\n"
	    "      --null-stdout    discard target stdout\n"
	    "      --null-stderr    discard target stderr\n"
	    "  -h, --help           show this help and exit\n"
	    "      --version        show version and exit\n"
	    "      --               end of zdbg options\n"
	    "\n"
	    "exit status:\n"
	    "  0  success\n"
	    "  1  a command failed in a script or batch session\n"
	    "  2  usage / setup / script-file-open error\n");
}

static void
print_version(void)
{
	printf("zdbg %d.%d\n",
	    ZDBG_VERSION_MAJOR, ZDBG_VERSION_MINOR);
}

struct zdbg_opts {
	const char *scripts[ZDBG_MAX_SCRIPT_FILES];
	int nscripts;
	int batch;
	int quiet;
	int verbose;
	int no_init;
	int target_argc;
	char **target_argv;
	const char *stdin_path;
	const char *stdout_path;
	const char *stderr_path;
	int capture_stdout;
	int capture_stderr;
	int null_stdin;
	int null_stdout;
	int null_stderr;
};

/*
 * Parse argv into opts.  Returns 0 on success, -1 on a usage
 * error (already printed), 1 if --help was given, 2 if --version
 * was given.
 */
static int
parse_opts(int argc, char **argv, struct zdbg_opts *o)
{
	int i;

	memset(o, 0, sizeof(*o));
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (a[0] != '-' || a[1] == 0) {
			/* First positional: target plus its args. */
			o->target_argc = argc - i;
			o->target_argv = argv + i;
			return 0;
		}
		if (strcmp(a, "--") == 0) {
			i++;
			if (i < argc) {
				o->target_argc = argc - i;
				o->target_argv = argv + i;
			}
			return 0;
		}
		if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)
			return 1;
		if (strcmp(a, "--version") == 0)
			return 2;
		if (strcmp(a, "-b") == 0 || strcmp(a, "--batch") == 0) {
			o->batch = 1;
			continue;
		}
		if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
			o->quiet = 1;
			continue;
		}
		if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
			o->verbose = 1;
			continue;
		}
		if (strcmp(a, "--no-init") == 0) {
			o->no_init = 1;
			continue;
		}
		if (strcmp(a, "-x") == 0 || strcmp(a, "--execute") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
				    "zdbg: %s requires a path\n", a);
				return -1;
			}
			if (o->nscripts >= ZDBG_MAX_SCRIPT_FILES) {
				fprintf(stderr,
				    "zdbg: too many -x scripts "
				    "(max %d)\n",
				    ZDBG_MAX_SCRIPT_FILES);
				return -1;
			}
			o->scripts[o->nscripts++] = argv[++i];
			continue;
		}
		if (strcmp(a, "--stdin") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
				    "zdbg: %s requires a path\n", a);
				return -1;
			}
			o->stdin_path = argv[++i];
			continue;
		}
		if (strcmp(a, "--stdout") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
				    "zdbg: %s requires a path\n", a);
				return -1;
			}
			o->stdout_path = argv[++i];
			continue;
		}
		if (strcmp(a, "--stderr") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
				    "zdbg: %s requires a path\n", a);
				return -1;
			}
			o->stderr_path = argv[++i];
			continue;
		}
		if (strcmp(a, "--capture-stdout") == 0) {
			o->capture_stdout = 1;
			continue;
		}
		if (strcmp(a, "--capture-stderr") == 0) {
			o->capture_stderr = 1;
			continue;
		}
		if (strcmp(a, "--null-stdin") == 0) {
			o->null_stdin = 1;
			continue;
		}
		if (strcmp(a, "--null-stdout") == 0) {
			o->null_stdout = 1;
			continue;
		}
		if (strcmp(a, "--null-stderr") == 0) {
			o->null_stderr = 1;
			continue;
		}
		fprintf(stderr, "zdbg: unknown option: %s\n", a);
		return -1;
	}
	return 0;
}

/*
 * Build the default startup-file path in `out`.  Returns 1 if a
 * candidate path was produced, 0 otherwise.
 */
static int
startup_path(char *out, size_t outlen)
{
	const char *home;

#if defined(_WIN32)
	home = getenv("USERPROFILE");
#else
	home = getenv("HOME");
#endif
	if (home == NULL || home[0] == 0)
		return 0;
	if ((size_t)snprintf(out, outlen, "%s/.zdbgrc", home) >= outlen)
		return 0;
	return 1;
}

/*
 * Run the optional startup file.  A missing file is silently
 * ignored.  Other errors are warned about but not fatal.
 */
static void
maybe_run_startup(struct zdbg *d)
{
	char path[1024];
	FILE *fp;
	int rc;

	if (!startup_path(path, sizeof(path)))
		return;
	fp = fopen(path, "r");
	if (fp == NULL)
		return;
	rc = zcmd_source_stream(d, fp, path);
	fclose(fp);
	if (rc != 0)
		fprintf(stderr,
		    "zdbg: warning: startup file %s reported errors\n",
		    path);
}

int
main(int argc, char **argv)
{
	struct zdbg d;
	struct zdbg_opts o;
	int parse_rc;
	int i;
	int exit_code = ZDBG_EXIT_OK;
	int ran_script = 0;

	parse_rc = parse_opts(argc, argv, &o);
	if (parse_rc == 1) {
		usage(stdout);
		return ZDBG_EXIT_OK;
	}
	if (parse_rc == 2) {
		print_version();
		return ZDBG_EXIT_OK;
	}
	if (parse_rc < 0) {
		usage(stderr);
		return ZDBG_EXIT_SETUP;
	}

	zdbg_init(&d);
	d.quiet = o.quiet;
	d.verbose = o.verbose;
	if (o.target_argc > 0) {
		d.target_argc = o.target_argc;
		d.target_argv = o.target_argv;
	}

	/* Apply CLI stdio options before any -x script may run `l`. */
	if (o.null_stdin)
		(void)zstdio_set_null(&d.stdio.in);
	else if (o.stdin_path != NULL) {
		if (zstdio_set_file(&d.stdio.in, o.stdin_path) < 0) {
			fprintf(stderr, "zdbg: --stdin: bad path\n");
			zdbg_fini(&d);
			return ZDBG_EXIT_SETUP;
		}
	}
	if (o.null_stdout)
		(void)zstdio_set_null(&d.stdio.out);
	else if (o.capture_stdout) {
		if (zstdio_set_capture(&d.stdio.out, "stdout") < 0) {
			fprintf(stderr, "zdbg: --capture-stdout failed\n");
			zdbg_fini(&d);
			return ZDBG_EXIT_SETUP;
		}
		if (!o.quiet)
			printf("stdout capture: %s\n", d.stdio.out.path);
	} else if (o.stdout_path != NULL) {
		if (zstdio_set_file(&d.stdio.out, o.stdout_path) < 0) {
			fprintf(stderr, "zdbg: --stdout: bad path\n");
			zdbg_fini(&d);
			return ZDBG_EXIT_SETUP;
		}
	}
	if (o.null_stderr)
		(void)zstdio_set_null(&d.stdio.err);
	else if (o.capture_stderr) {
		if (zstdio_set_capture(&d.stdio.err, "stderr") < 0) {
			fprintf(stderr, "zdbg: --capture-stderr failed\n");
			zdbg_fini(&d);
			return ZDBG_EXIT_SETUP;
		}
		if (!o.quiet)
			printf("stderr capture: %s\n", d.stdio.err.path);
	} else if (o.stderr_path != NULL) {
		if (zstdio_set_file(&d.stdio.err, o.stderr_path) < 0) {
			fprintf(stderr, "zdbg: --stderr: bad path\n");
			zdbg_fini(&d);
			return ZDBG_EXIT_SETUP;
		}
	}

	if (!o.quiet && !o.batch)
		banner();

	if (o.target_argc > 0 && !o.quiet)
		printf("target: %s (type `l` to launch)\n",
		    o.target_argv[0]);

	if (!o.no_init)
		maybe_run_startup(&d);

	/* Run any -x scripts in order. */
	for (i = 0; i < o.nscripts; i++) {
		int rc;

		ran_script = 1;
		rc = zcmd_source_file(&d, o.scripts[i]);
		if (rc == -2) {
			exit_code = ZDBG_EXIT_SETUP;
			goto done;
		}
		if (rc != 0) {
			exit_code = ZDBG_EXIT_CMD_FAIL;
			goto done;
		}
		if (d.quit_requested)
			goto done;
	}

	if (o.batch) {
		if (!ran_script) {
			/*
			 * Batch with no -x: read commands from stdin
			 * if it is not a terminal.  A terminal stdin
			 * is a usage error.
			 */
			if (ZDBG_ISATTY(ZDBG_FILENO(stdin))) {
				fprintf(stderr,
				    "zdbg: no script specified for "
				    "batch mode\n");
				exit_code = ZDBG_EXIT_SETUP;
				goto done;
			}
			if (zcmd_source_stream(&d, stdin, "<stdin>") != 0)
				exit_code = ZDBG_EXIT_CMD_FAIL;
		}
		goto done;
	}

	/* Interactive: drop into the REPL unless quit was requested. */
	if (!d.quit_requested)
		zrepl_run(&d);

done:
	if (exit_code == ZDBG_EXIT_OK && d.had_error && (o.batch || ran_script))
		exit_code = ZDBG_EXIT_CMD_FAIL;
	zdbg_fini(&d);
	return exit_code;
}
