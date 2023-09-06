#include "ft_ssl.h"

void print_error_by_message(const t_master* master, const char* message) {
	yoyo_dprintf(STDERR_FILENO, "%s: %s: %s\n", master->program_name, master->command_name, message);
}

void print_error_by_errno(const t_master* master) {
	yoyo_dprintf(STDERR_FILENO, "%s: %s: %s\n", master->program_name, master->command_name, strerror(errno));
}
