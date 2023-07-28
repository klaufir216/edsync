#include <sys/ioctl.h>

int get_term_width(void) {
    struct winsize ws;
    ioctl(1, TIOCGWINSZ, &ws);
    return ws.ws_col;
}

int get_term_height(void) {
    struct winsize ws;
    ioctl(1, TIOCGWINSZ, &ws);
    return ws.ws_row;
}
