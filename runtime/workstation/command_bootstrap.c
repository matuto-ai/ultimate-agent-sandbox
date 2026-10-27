/* Explicit separate source profile. Four includes two helpers and their one
 * directly owned command each; each command lowers its own NPROC to one and
 * receives a seccomp profile that denies every process-creation operation. */
#define AG_NPROC 64U
#define AG_EVALUATOR "/opt/uas/bin/command-evaluator"
#include "artifact_bootstrap.c"
