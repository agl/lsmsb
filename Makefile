default: lsmsb-as lsmsb-install lsmsb.html

lsmsb.html: lsmsb.aw
	aweb --no-location-lines lsmsb.aw

lsmsb.c: lsmsb.aw
	aweb --no-location-lines lsmsb.aw

lsmsb-as.rl: lsmsb.aw
	aweb --no-location-lines lsmsb.aw

lsmsb-install.c: lsmsb.aw
	aweb --no-location-lines lsmsb.aw

lsmsb-as.cc: lsmsb-as.rl
	ragel -o lsmsb-as.cc lsmsb-as.rl

lsmsb-as: lsmsb-as.cc
	g++ -o lsmsb-as -Wall lsmsb-as.cc -ggdb

lsmsb-install: lsmsb-install.c
	gcc -o lsmsb-install lsmsb-install.c -Wall
