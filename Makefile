CFLAGS=-std=c11 -Wall -Wextra -Werror -fanalyzer

aqi: aqi.c
	gcc $(CFLAGS) $< -o $@
