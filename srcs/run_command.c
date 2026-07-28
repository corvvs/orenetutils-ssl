#include "ft_ssl.h"

static const struct s_command_category_title {
	t_command_category	category;
	const char*			title;
}	g_command_category_titles[] = {
	{ COMMAND_CATEGORY_STANDARD, "Standard commands" },
	{ COMMAND_CATEGORY_DIGEST,   "Message Digest commands" },
	{ COMMAND_CATEGORY_CIPHER,   "Cipher commands" },
};

static void	show_commands_in_category(t_command_category category) {
	for (unsigned int i = 0; g_command_pairs[i].name != NULL; ++i) {
		if (g_command_pairs[i].category == category) {
			yoyo_dprintf(STDERR_FILENO, "%s\n", g_command_pairs[i].name);
		}
	}
}

static void	show_help(void) {
	const unsigned int	n = sizeof(g_command_category_titles) / sizeof(g_command_category_titles[0]);
	for (unsigned int i = 0; i < n; ++i) {
		if (i > 0) {
			yoyo_dprintf(STDERR_FILENO, "\n");
		}
		yoyo_dprintf(STDERR_FILENO, "%s:\n", g_command_category_titles[i].title);
		show_commands_in_category(g_command_category_titles[i].category);
	}
}

void	show_usage(const t_master* master) {
	yoyo_dprintf(STDERR_FILENO, "usage: %s command [command opts] [command args]\n", master->program_name);
}

int run_help(t_master *master, char **arguments) {
	(void)arguments;
	if (!master->in_repl) {
		yoyo_dprintf(STDERR_FILENO, "help:\n\n");
	}
	show_help();
	yoyo_dprintf(STDERR_FILENO, "\n");
	return 0;
}

t_command_pair	get_command(const char* name) {
	size_t n = sizeof(g_command_pairs) / sizeof(g_command_pairs[0]);
	if (name != NULL) {
		for (unsigned int i = 0; i < n; ++i) {
			if (g_command_pairs[i].name == NULL) {
				break;
			}
			if (ft_strcmp(name, g_command_pairs[i].name) == 0) {
				return g_command_pairs[i];
			}
		}
	}
	return g_command_pairs[n - 1];
}

static int	exec_command(t_master* master, char **arguments) {
	if (master->command.func == NULL) {
		if (*master->command_name) {
			yoyo_dprintf(STDERR_FILENO, "%s: Error: '%s' is an invalid command.\n", master->program_name, master->command_name);
			if (master->in_repl) {
				yoyo_dprintf(STDERR_FILENO, "error in %s\n", master->command_name);
			} else {
				yoyo_dprintf(STDERR_FILENO, "\n");
				show_help();
			}
		}
		return 1;
	}
	return master->command.func(master, arguments);
}

int	run_command(t_master* master, const char* command_name, char** const arguments) {
	if (command_name == NULL) {
		return 1;
	}
	master->command = get_command(command_name);
	master->command_name = command_name;
	return exec_command(master, arguments);
}
