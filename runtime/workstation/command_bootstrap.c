/* Separate fixed command profile. The command lowers its own hard process
 * and memory limits, inherits the bounded nonescaping child-tree filter, and
 * receives only an immutable target and a separately owned 8 MiB work lease. */
#define AG_NPROC 64U
#define AG_FSIZE (8U*1024U*1024U)
#define AG_COMMAND_WORK 1
#define AG_EVALUATOR "/opt/uas/bin/command-evaluator"
#include "artifact_bootstrap.c"
