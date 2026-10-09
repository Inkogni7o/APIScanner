#include <cstdlib>

void release() {
    char *buffer = static_cast<char *>(malloc(32));
    free(buffer);
}
