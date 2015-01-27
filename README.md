# garpd

`garpd` is a fast, simple daemon that listens for and reports gratuitous ARP
messages.

## Compiling

`garpd` is extremely simple. To compile it, just run:

    gcc -ogarpd garpd.c 

That will build an executable called `garpd` in your working directory,
which can be copied anywhere you want for installation. It does not
require linking with any libraries other than libc.

## Using garpd

When you run `garpd`, it will create a Unix socket at `/var/opt/garpd.sck`.
Each time it finds a gratuitous ARP message it will write a JSON dictionary
into the socket, terminated by a newline. The format of the dictionary is:

    {"ip": "<dotted decimal IP>", "mac": "<colon-separated MAC>"}

There are guaranteed to be no newlines in the body, so a simple parser can
scan for newlines and split on them.

