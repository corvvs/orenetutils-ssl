#include "ft_ssl.h"

static void	show_help(void) {
	yoyo_dprintf(STDERR_FILENO,
		"Commands:\n"
	);
	for (unsigned int i = 0; i < sizeof(g_command_pairs) / sizeof(g_command_pairs[0]); ++i) {
		if (g_command_pairs[i].name == NULL) {
			break;
		}
		yoyo_dprintf(STDERR_FILENO, "%s\n", g_command_pairs[i].name);
	}
	yoyo_dprintf(STDERR_FILENO, "\n");
	yoyo_dprintf(STDERR_FILENO,
		"Flags:\n"
		"-p -q -r -s\n"
	);
}
int run_help(t_master *master, char **argv) {
	(void)argv;
	if (!master->in_repl) {
		yoyo_dprintf(STDERR_FILENO, "help:\n\n");
	}
	show_help();
	yoyo_dprintf(STDERR_FILENO, "\n");
	return 0;
}

int	run_command(t_master* master, char **argv) {
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
	return master->command.func(master, argv);
}
