#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <assert.h>
#include <poll.h>

#define TTY_DEV "/dev/ttyS0"
#define CMD_PASSIVE 0xe1
#define CMD_READ 0xe2
#define MAX_HEADER_SIZE 4096
#define PACKET_HEADER_MAGIC (htonl(0x424d001c))

#define TTY_READ_TIMEOUT 100
#define TCP_READ_TIMEOUT 1000

static const char fmt[] = 
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/plain\r\n\r\n"
"# TYPE success gauge\r\n"
"success 1\r\n"
"# TYPE pm gauge\r\n"
"pm{size=\"1.0\"} %d\r\n"
"pm{size=\"2.5\"} %d\r\n"
"pm{size=\"10.0\"} %d\r\n"
"pm{size=\"1.0\",atmospheric=\"true\"} %d\r\n"
"pm{size=\"2.5\",atmospheric=\"true\"} %d\r\n"
"pm{size=\"10.0\",atmospheric=\"true\"} %d\r\n"
"# TYPE n gauge\r\n"
"n{size=\"0.3\"} %d\r\n"
"n{size=\"0.5\"} %d\r\n"
"n{size=\"1.0\"} %d\r\n"
"n{size=\"2.5\"} %d\r\n"
"n{size=\"5.0\"} %d\r\n"
"n{size=\"10.0\"} %d\r\n";

static const char error_msg[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
				"# Type success gauge\r\nsuccess 0\r\n";
static const char entity_too_large_msg[] = "HTTP/1.1 413 Entity Too Large\r\n\r\nHeader size max: 4k\r\n";
static const char internal_err_msg[] = "HTTP/1.1 500 Internal Server Error\r\n\r\nOops\r\n";
static const char timeout_msg[] = "HTTP/1.1 408 Request Timeout\r\n\r\nOops\r\n";

// packet is all big endian. Since network order is BE, use htons/htonl to convert
// doesn't need to be packed since everything is already aligned.
struct packet {
	uint32_t header; //must be BM\x00\x1c
	uint16_t data[12];
	uint8_t _padding[2];
	uint16_t check;
};
static_assert(sizeof(struct packet) == 32, "packet structure is the wrong size");

// command is all big endian. Must be packed
struct __attribute__((__packed__)) command {
	uint8_t header[2];
	uint8_t cmd;
	uint8_t args[2];
	uint16_t check;
};
static_assert(sizeof(struct command) == 7, "command structure is the wrong size");

static void write_sensor_response(int sock, int tty_fd);
static int read_until_end(int sock);
static int send_cmd(int fd, char cmd, char arg1, char arg2, void *buf, size_t len);
static int setup_tty(const char *dev);

/*
 * read up end a double newline or until we've read MAX_HEADER_SIZE, whichever comes first
 * returns -1 if recv fails (and leaves errno set)
 * returns -2 if two newlines were not read
 */
static int read_until_end(int sock) {
	char buffer[MAX_HEADER_SIZE];
	size_t len = 0;
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLIN;
	while (len < sizeof(buffer)) {
		int poll_ret = poll(&pfd, 1, TCP_READ_TIMEOUT);
		if (poll_ret == -1) {
			perror("poll failed on tcp socket");
			return -1;
		}
		if (poll_ret == 0) {
			return -3;
		}
		ssize_t ret = recv(sock, buffer + len, sizeof(buffer) - len, 0);
		if (ret == -1) {
			perror("failed receiving from client socket");
			return -1;
		}
		len += ret;

		// we don't really care if the client is making a valid http request or not,
		// so if all they do is send two newlines that's alright with us.
		if (len >= 4 && (memcmp(buffer+len-4, "\r\n\r\n", 4) == 0 ||
				memcmp(buffer+len-4, "\n\r\n\r", 4) == 0 ||
				memcmp(buffer+len-2, "\n\n", 2) == 0)) {
			return 0;
		}
	}

	fputs("client exceded max header size\n", stderr);
	return -2;
}

/*
 * Sends the command cmd on the serial connection fd. arg1 and arg2 are the high and low bytes
 * of the argument. Reads len bytes into buf after sending the command.
 *
 * returns:
 * 	0 on success
 * 	-1 if read or write fail, or they succeed but do not write the read the full command
 * 	   or response
 */
static int send_cmd(int fd, char cmd, char arg1, char arg2, void *buf, size_t len) {
	struct command c = {
		.header = {'B', 'M'},
		.cmd = cmd,
		.args = {arg1, arg2},
	};

	// calculate checksum
	uint16_t check = 0;
	for (int i = 0; i < 5; i++) {
		check += ((uint8_t*)&c)[i];
	}
	c.check = htons(check);

	ssize_t cnt = write(fd, (void *)&c, sizeof(c));
	if (cnt == -1) {
		perror("failed to write to tty");
		return -1;
	}
	if (cnt != (ssize_t)sizeof(c)) {
		fputs("failed to write entire command to tty\n", stderr);
		return -1;
	}

	// The sensor sometimes misses the command which would leave read() hanging.
	// poll() first to make sure it wont hang since even with VTIME set to non-zero
	// in the termios settings (see man 3 termios) it will block indefinitely on the
	// first byte
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	int poll_ret = poll(&pfd, 1, TTY_READ_TIMEOUT);
	if (poll_ret == -1) {
		perror("poll failed");
		return -1;
	} else if (poll_ret == 0) {
		fputs("sensor did not respond\n", stderr);
		return -1;
	}

	cnt = read(fd, buf, len);
	if (cnt == -1) {
		perror("failed to read from tty");
		return -1;
	}
	if (cnt != (ssize_t)len) {
		fprintf(stderr, "read %d, wanted %d buf=%p\n", cnt, len, buf);
		return -1;
	}
	return 0;
}

/*
 * Sets up the tty device (e.g. /dev/ttyS0) to be a raw tty device, returning its file descriptor.
 * returns
 * 	the file descriptor if successful
 * 	-1 for all errors that set errno
 */
static int setup_tty(const char *dev) {
	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		perror("opening tty failed");
		return -1;
	}

	struct termios tty;
	if (tcgetattr(fd, &tty) != 0) {
		perror("failed to read tty settings");
		return -1;
	}

	tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
			| INLCR | IGNCR | ICRNL | IXON | IXOFF | IXANY);
	tty.c_oflag &= ~(OPOST | ONLCR);
	tty.c_lflag &= ~(ECHO | ECHOE | ECHONL | ICANON | ISIG | IEXTEN);
	tty.c_cflag &= ~(CSIZE | PARENB | CSTOPB);
	tty.c_cflag |= CS8 | CREAD | CLOCAL;

	tty.c_cc[VTIME] = 10; // 1 second
	tty.c_cc[VMIN] = 8;

	cfsetospeed(&tty, B9600);
	cfsetispeed(&tty, B9600);

	if (tcsetattr(fd, TCSANOW, &tty) == -1) {
		perror("failed to set tty settings");
		return -1;
	}
	if (tcflush(fd, TCIOFLUSH) == -1) {
		perror("failed to flush tty");
		return -1;
	}

	char dummy[8];
	int err = send_cmd(fd, CMD_PASSIVE, 0, 0, &dummy, 8);
	if (err != 0) {
		return err;
	}

	tty.c_cc[VMIN] = sizeof(struct packet);
	if (tcsetattr(fd, TCSANOW, &tty) == -1) {
		perror("failed to set tty settings");
		return -1;
	}

	return fd;
}

void write_sensor_response(int sock, int tty_fd) {
	struct packet p;
	int err = send_cmd(tty_fd, CMD_READ, 0, 0, &p, sizeof(p));
	if (err == -1) {
		// try again, sometimes the sensor misses a request
		err = send_cmd(tty_fd, CMD_READ, 0, 0, &p, sizeof(p));
	}
	int check = 0;
	for (int i = 0; i < 30; i++) {
		check += ((uint8_t*)&p)[i];
	}


	if (err == -1 || check != htons(p.check) || p.header != PACKET_HEADER_MAGIC) {
		err = write(sock, error_msg, sizeof(error_msg) - 1); // don't write nul
	} else {
		err = dprintf(sock, fmt, htons(p.data[0]),
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
	if (err == -1) {
		fputs("error writing response to client socket\n", stderr);
	}
}

int main(int argc, char **argv) {
	if (argc < 3 || argc > 4) {
		fputs("usage: aqi host port [ttyS0]\n", stderr);
		return 1;
	}

	char *host = argv[1];
	char *port_str = argv[2];
	char *dev = (argc == 4) ? argv[3] : TTY_DEV;

	int tty_fd = setup_tty(dev);
	if (tty_fd == -1) {
		return -1;
	}

	errno = 0;
	int port = strtol(port_str, NULL, 10);
	if (errno) {
		perror("failed to parse port number");
		return 1;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = inet_addr(host),
	};
	if (addr.sin_addr.s_addr == INADDR_NONE) {
		fputs("failed to parse host address\n", stderr);
		return 1;
	}


	int sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd == -1) {
		perror("error opening socket");
		return 1;
	}

	if (bind(sfd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
		perror("error binding socket");
		return 1;
	}

	if (listen(sfd, 10) == -1) {
		perror("error making socket listen");
		return 1;
	}

	while (1) {
		int sock = accept(sfd, NULL, NULL);
		if (sock == -1) {
			perror("error accepting connection, continuing");
			continue;
		}
		int err = read_until_end(sock);
		switch (err) {
			case -1:
				write(sock, internal_err_msg, sizeof(internal_err_msg) - 1);
				break;
			case -2:
				write(sock, entity_too_large_msg, sizeof(entity_too_large_msg) - 1);
				break;
			case -3:
				write(sock, timeout_msg, sizeof(timeout_msg) - 1);
				break;
			default:
				write_sensor_response(sock, tty_fd);
		}

		shutdown(sock, SHUT_RDWR);
		close(sock);
	}
}
