CFLAGS=-std=c11 -Wall -Wextra -Werror -O2 -g

aqi: aqi.c
	gcc $(CFLAGS) $< -o $@
