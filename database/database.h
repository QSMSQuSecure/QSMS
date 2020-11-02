#include "data.h"

pub_t *readBuf(data_t *data, buffer_t *buffer);

pub_t *userReadPub(data_t *data, read_t *input);

pub_t *userWrite(data_t *data, write_t *input);

void readBuffer(data_t *data, int sock);

void error(char *msg);
