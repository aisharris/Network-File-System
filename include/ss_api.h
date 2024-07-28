#ifndef __SS_API_H_
#define __SS_API_H_

#include "ccp.h"

int ss_command(sockinfo ss_to, char* path, int pathlen, uint8_t cmd, char* copy_path, int copy_pathlen, ss_info ss_from);

#endif
