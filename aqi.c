#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>

#define TTY_DEV "/dev/ttyS0"
#define CMD_PASSIVE 0xe1
#define CMD_READ 0xe2

static const char fmt[] = 
"HTTP/1.0 200 OK\n"
"Content-Type: text/plain\n\n"
"# TYPE success gauge\n"
"success 1\n"
"# TYPE pm gauge\n"
"pm{size=\"1.0\"} %d\n"
"pm{size=\"2.5\"} %d\n"
"pm{size=\"10.0\"} %d\n"
"pm{size=\"1.0\",atmospheric=\"true\"} %d\n"
"pm{size=\"2.5\",atmospheric=\"true\"} %d\n"
"pm{size=\"10.0\",atmospheric=\"true\"} %d\n"
"# TYPE n gauge\n"
"n{size=\"0.3\"} %d\n"
"n{size=\"0.5\"} %d\n"
"n{size=\"1.0\"} %d\n"
"n{size=\"2.5\"} %d\n"
"n{size=\"5.0\"} %d\n"
"n{size=\"10.0\"} %d\n";

struct packet {
	uint32_t header; //must be BM\x00\x1c
	uint16_t data[12];
	uint8_t _padding[2];
	uint16_t check;
};

struct command {
	uint8_t header[2];
	uint8_t cmd;
	uint8_t args[2];
	uint16_t check;
};

void send_cmd(int fd, char cmd, char arg1, char arg2, void *buf, size_t len) {
	struct command c = {
		.header = {'B', 'M'},
		.cmd = cmd,
		.args = {arg1, arg2},
	};
	uint16_t check = 0;
	for (int i = 0; i < 5; i++) {
		check += ((uint8_t*)&c)[i];
	}
	c.check = htons(check);
	
	write(fd, (void *)&c, sizeof(c));
	read(fd, buf, len);
}

int setup_tty(const char *dev) {
	int fd = open(dev, O_RDWR);
	if (!fd) {
		return 0;
	}

	struct termios tty;
	if (tcgetattr(fd, &tty) != 0) {
		return -1;
	}
	// equivilent to cfmakeraw, code from `man 3 termios`
	tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
			| INLCR | IGNCR | ICRNL | IXON);
	tty.c_oflag &= ~OPOST;
	tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	tty.c_cflag &= ~(CSIZE | PARENB);
	tty.c_cflag |= CS8;
	cfsetospeed(&tty, B9600);
	cfsetispeed(&tty, B9600);

	if (tcsetattr(fd, TCSANOW, &tty) != 0) {
		return -2;
	}

	char dummy[8];
	send_cmd(fd, CMD_PASSIVE, 0, 0, dummy, 8);
	return fd;
}

int main(int argc, char **argv) {
	if (argc < 3 || argc > 4) {
		return 1;
	}

	char *host = argv[1];
	char *port_str = argv[2];
	char *dev = TTY_DEV;
	if (argc == 4) {
		dev = argv[3];
	}
	int tty_fd = setup_tty(dev);

	int port = strtol(port_str, NULL, 10);
	if (errno) {
		return 2;
	}
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = inet_addr(host),
	};
	if (addr.sin_addr.s_addr == INADDR_NONE) {
		return 3;
	}


	int sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (!sfd) {
		return 4;
	}
	int err = bind(sfd, (struct sockaddr*) &addr, sizeof(addr));
	if (err) {
		return 5;
	}
	if (listen(sfd, 10) != 0) {
		return 6;
	}
	while (1) {
		int sock = accept(sfd, NULL, NULL);
		if (sock == -1) {
			return 7;
		}
		struct packet p;
		send_cmd(tty_fd, CMD_READ, 0, 0, &p, 32);
		int check = 0;
		for (int i = 0; i < 30; i++) {
			check += ((uint8_t*)&p)[i];
		}
		if (check != htons(p.check) || p.header != htonl(0x424d001c)) {
			dprintf(sock, "HTTP/1.0 200 OK\nContent-Type: text/plain\n\n"
					"# Type success gauge\nsuccess 0");
		} else {
			dprintf(sock, fmt, htons(p.data[0]),
					htons(p.data[1]),
					htons(p.data[2]),
					htons(p.data[3]),
					htons(p.data[4]),
					htons(p.data[5]),
					htons(p.data[6]),
					htons(p.data[7]),
					htons(p.data[8]),
					htons(p.data[9]),
					htons(p.data[10]),
					htons(p.data[11]));
		}

		shutdown(sock, SHUT_RDWR);
		close(sock);
	}
}
