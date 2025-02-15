// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cmd.h"
#include "utils.h"

#define READ   0
#define WRITE  1

#ifndef SHELL_EXIT
#define SHELL_EXIT 123
#endif

#define IO_OUT_APPEND      0x01
#define IO_ERR_APPEND      0x02
#define IO_OUT_ERR         0x04
#define IO_OUT_ERR_APPEND  0x08

static void handle_redirections_in_parent(simple_command_t *s)
{
	if (!s)
		return;

	if (s->in) {
		char *infile = get_word(s->in);
		int fd_in = open(infile, O_RDONLY);

		if (fd_in < 0) {
			fprintf(stderr, "Unable to open %s: %s\n", infile, strerror(errno));
			free(infile);
			return;
		}
		dup2(fd_in, STDIN_FILENO);
		close(fd_in);
		free(infile);
	}

	if ((s->io_flags & IO_OUT_ERR) || (s->io_flags & IO_OUT_ERR_APPEND)) {
		char *outerrfile = get_word(s->out);

		int flags = O_WRONLY | O_CREAT;

		if (s->io_flags & IO_OUT_ERR_APPEND)
			flags |= O_APPEND;
		else
			flags |= O_TRUNC;

		int fd_outerr = open(outerrfile, flags, 0664);

		if (fd_outerr < 0) {
			fprintf(stderr, "Unable to open %s: %s\n", outerrfile, strerror(errno));
			free(outerrfile);
			return;
		}

		dup2(fd_outerr, STDOUT_FILENO);
		dup2(fd_outerr, STDERR_FILENO);
		close(fd_outerr);
		free(outerrfile);

		return;
	}

	if (s->out) {
		char *outfile = get_word(s->out);
		int flags = O_WRONLY | O_CREAT;

		if (s->io_flags & IO_OUT_APPEND)
			flags |= O_APPEND;
		else
			flags |= O_TRUNC;

		int fd_out = open(outfile, flags, 0664);

		if (fd_out < 0) {
			fprintf(stderr, "Unable to open %s: %s\n", outfile, strerror(errno));
			return;
		}
		dup2(fd_out, STDOUT_FILENO);
		close(fd_out);
	}

	if (s->err) {
		char *errfile = get_word(s->err);
		int flags = O_WRONLY | O_CREAT;

		if (s->io_flags & IO_ERR_APPEND)
			flags |= O_APPEND;
		else
			flags |= O_TRUNC;

		int fd_err = open(errfile, flags, 0664);

		if (fd_err < 0) {
			fprintf(stderr, "Unable to open %s: %s\n", errfile, strerror(errno));
			free(errfile);
			return;
		}
		dup2(fd_err, STDERR_FILENO);
		close(fd_err);
		free(errfile);
	}
}

static const char *handle_token(word_t *word)
{
	if (word->expand)
		return getenv(word->string) ? getenv(word->string) : "";
	else
		return word->string;
}

static char *get_value(word_t *token)
{
	if (!token)
		return NULL;

	char *value = strdup(handle_token(token));

	while (token->next_part) {
		token = token->next_part;
		value = realloc(value, strlen(value) + strlen(handle_token(token)) + 1);
		strcat(value, handle_token(token));
	}

	return value;
}

static void handle_redirections(simple_command_t *s)
{
	if (!s)
		return;

	char *out_val = get_value(s->out);
	char *err_val = get_value(s->err);

	if (s->in) {
		char *infile = get_word(s->in);
		int fd_in = open(infile, O_RDONLY);

		if (fd_in < 0) {
			perror("open <");
			free(infile);
			_exit(1);
		}
		dup2(fd_in, STDIN_FILENO);
		close(fd_in);
		free(infile);
	}

	if (s->out && s->err  && !strcmp(out_val, err_val)) {
		char *outerrfile = get_word(s->out);
		int flags = O_WRONLY | O_CREAT;

		if (s->io_flags & IO_OUT_ERR_APPEND)
			flags |= O_APPEND;
		else
			flags |= O_TRUNC;

		int fd_outerr = open(outerrfile, flags, 0664);

		if (fd_outerr < 0) {
			perror("open &>");
			free(outerrfile);
			_exit(1);
		}
		dup2(fd_outerr, STDOUT_FILENO);
		dup2(fd_outerr, STDERR_FILENO);
		close(fd_outerr);
		free(outerrfile);

	} else {
		if (s->out) {
			char *outfile = get_word(s->out);
			int flags = O_WRONLY | O_CREAT;

			if (s->io_flags & IO_OUT_APPEND)
				flags |= O_APPEND;
			else
				flags |= O_TRUNC;
			int fd_out = open(outfile, flags, 0664);

			if (fd_out < 0) {
				perror("open >");
				free(outfile);
				_exit(1);
			}
			dup2(fd_out, STDOUT_FILENO);
			close(fd_out);
			free(outfile);
		}

		if (s->err) {
			char *errfile = get_word(s->err);
			int flags = O_WRONLY | O_CREAT;

			if (s->io_flags & IO_ERR_APPEND)
				flags |= O_APPEND;
			else
				flags |= O_TRUNC;

			int fd_err = open(errfile, flags, 0664);

			if (fd_err < 0) {
				perror("open 2>");
				free(errfile);
				_exit(1);
			}
			dup2(fd_err, STDERR_FILENO);
			close(fd_err);
			free(errfile);
		}
	}
}

static bool shell_cd(word_t *dir)
{
	if (!dir)
		return true;

	int arg_count = 0;
	char *target = NULL;

	for (word_t *p = dir; p; p = p->next_word) {
		arg_count++;
		if (arg_count == 1)
			target = get_word(p);
	}
	if (arg_count != 1) {
		if (target)
			free(target);
		return true;
	}

	if (chdir(target) < 0) {
		fprintf(stderr, "no such file or directory\n");
		free(target);
		return false;
	}
	free(target);
	return true;
}

static int shell_exit(void)
{
	return SHELL_EXIT;
}

static bool is_assignment(const char *str)
{
	if (!str)
		return false;
	const char *eq = strchr(str, '=');

	if (!eq)
		return false;
	if (eq == str)
		return false;
	if (*(eq+1) == '\0')
		return false;
	return true;
}

static int do_assignment(const char *str)
{
	char *eq = strchr(str, '=');

	if (!eq)
		return -1;

	size_t key_len = eq - str;
	char *key = calloc(key_len + 1, sizeof(char));

	if (!key)
		return -1;

	strncpy(key, str, key_len);
	const char *value = eq + 1;

	if (setenv(key, value, 1) < 0) {
		fprintf(stderr, "Failed to set variable '%s'\n", key);
		free(key);
		return -1;
	}
	free(key);
	return 0;
}

static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s)
		return 0;
	if (!s->verb || !s->verb->string)
		return 0;

	char *cmd_name = get_word(s->verb);

	if (!cmd_name)
		return 0;

	if (strcmp(cmd_name, "cd") == 0) {
		int old_stdout = dup(STDOUT_FILENO);
		int old_stderr = dup(STDERR_FILENO);
		bool do_restore = (old_stdout >= 0 && old_stderr >= 0);

		handle_redirections_in_parent(s);
		bool ok = shell_cd(s->params);

		if (do_restore) {
			dup2(old_stdout, STDOUT_FILENO);
			dup2(old_stderr, STDERR_FILENO);
			close(old_stdout);
			close(old_stderr);
		}

		free(cmd_name);
		return ok ? 0 : 1;
	}

	if (strcmp(cmd_name, "exit") == 0 || strcmp(cmd_name, "quit") == 0) {
		free(cmd_name);
		return shell_exit();
	}

	if (!s->params && is_assignment(cmd_name)) {
		do_assignment(cmd_name);
		free(cmd_name);
		return 0;
	}

	int argc = 0;
	char **argv = get_argv(s, &argc);

	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		free(cmd_name);
		for (int i = 0; i < argc; i++)
			free(argv[i]);

		free(argv);
		return -1;
	} else if (pid == 0) {

		handle_redirections(s);

		setbuf(stdout, NULL);
		setbuf(stderr, NULL);

		if (strcmp(cmd_name, "pwd") == 0) {
			char cwd[4096];

			if (getcwd(cwd, sizeof(cwd)))
				printf("%s\n", cwd);
			else
				perror("getcwd");
			_exit(0);
		}

		execvp(argv[0], argv);
		fprintf(stderr, "Execution failed for '%s'\n", argv[0]);
		_exit(127);
	} else {
		int status;

		waitpid(pid, &status, 0);

		free(cmd_name);
		for (int i = 0; i < argc; i++)
			free(argv[i]);

		free(argv);

		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		else
			return -1;
	}
}

static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	pid_t pid1, pid2;
	int status1, status2;

	if ((pid1 = fork()) < 0) {
		perror("fork");
		return false;
	} else if (pid1 == 0) {
		_exit(parse_command(cmd1, level + 1, father));
	}

	if ((pid2 = fork()) < 0) {
		perror("fork");
		return false;
	} else if (pid2 == 0) {
		_exit(parse_command(cmd2, level + 1, father));
	}

	pid_t pids[2] = {pid1, pid2};
	int statuses[2];

	for (int i = 0; i < 2; i++)
		waitpid(pids[i], &statuses[i], 0);

	return (WIFEXITED(status1) && WEXITSTATUS(status1) == 0) &&
		   (WIFEXITED(status2) && WEXITSTATUS(status2) == 0);
}

static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	int pipefd[2];

	if (pipe(pipefd) < 0) {
		perror("pipe");
		return false;
	}

	pid_t pids[2];
	int statuses[2];

	if ((pids[0] = fork()) < 0) {
		perror("fork");
		return false;
	}
	if (pids[0] == 0) {
		close(pipefd[READ]);
		dup2(pipefd[WRITE], STDOUT_FILENO);
		close(pipefd[WRITE]);
		int r1 = parse_command(cmd1, level + 1, father);

		_exit(r1);
	}

	if ((pids[1] = fork()) < 0) {
		perror("fork");
		return false;
	}
	if (pids[1] == 0) {
		close(pipefd[WRITE]);
		dup2(pipefd[READ], STDIN_FILENO);
		close(pipefd[READ]);
		int r2 = parse_command(cmd2, level + 1, father);

		_exit(r2);
	}

	close(pipefd[READ]);
	close(pipefd[WRITE]);

	for (int i = 0; i < 2; i++)
		waitpid(pids[i], &statuses[i], 0);


	return (WIFEXITED(statuses[1]) && WEXITSTATUS(statuses[1]) == 0);
}

int parse_command(command_t *c, int level, command_t *father)
{
	if (!c)
		return 0;

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	int status1;

	switch (c->op) {
	case OP_SEQUENTIAL:
		status1 = parse_command(c->cmd1, level + 1, c);
		return parse_command(c->cmd2, level + 1, c);

	case OP_PARALLEL:
		run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		return 0;

	case OP_CONDITIONAL_NZERO:
		status1 = parse_command(c->cmd1, level + 1, c);
		return (status1 != 0) ? parse_command(c->cmd2, level + 1, c) : status1;

	case OP_CONDITIONAL_ZERO:
		status1 = parse_command(c->cmd1, level + 1, c);
		return (status1 == 0) ? parse_command(c->cmd2, level + 1, c) : status1;

	case OP_PIPE: {
		bool result = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

		return result ? 0 : 1;
	}

	default:
		return SHELL_EXIT;
	}
}
