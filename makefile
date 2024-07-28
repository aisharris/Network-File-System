.DEFAULT_GOAL := all

ns: src/ns.c src/rbtree.c src/ccp.c src/ss_api.c
	gcc -Iinclude src/ns.c src/ccp.c src/rbtree.c src/ss_api.c -g -fsanitize=address -Wall -o ns

ss: src/ss.c src/ns_api.c src/ccp.c src/ss_api.c
	gcc -Iinclude src/ss.c src/ccp.c src/ns_api.c src/ss_api.c -g -fsanitize=address -Wall -o ss
	cp ss testpaths/ss1/
	cp ss testpaths/ss2/
	cp ss testpaths/ss3/
	cp ss testpaths/ss4/
	rm -f testpaths/ss1/ss_uid.txt
	rm -f testpaths/ss2/ss_uid.txt
	rm -f testpaths/ss3/ss_uid.txt
	rm -f testpaths/ss4/ss_uid.txt

client: src/client.c src/ccp.c src/ns_api.c src/ss_api.c
	gcc -Iinclude src/client.c src/ccp.c src/ns_api.c src/ss_api.c -g -fsanitize=address -Wall -o client

all: ns ss client

.PHONY: clean
clean:
	rm -f ns ss client
	rm -f testpaths/ss1/ss
	rm -f testpaths/ss2/ss
	rm -f testpaths/ss3/ss
	rm -f testpaths/ss4/ss
	rm -f testpaths/ss1/ss_uid.txt
	rm -f testpaths/ss2/ss_uid.txt
	rm -f testpaths/ss3/ss_uid.txt
	rm -f testpaths/ss4/ss_uid.txt
	rm -rf testpaths/ss1/2
	rm -rf testpaths/ss1/3
	rm -rf testpaths/ss1/4
	rm -rf testpaths/ss2/1
	rm -rf testpaths/ss2/3
	rm -rf testpaths/ss2/4
	rm -rf testpaths/ss3/1
	rm -rf testpaths/ss3/2
	rm -rf testpaths/ss1/NFS_READS
	rm -rf testpaths/ss2/NFS_READS
	rm -rf testpaths/ss3/NFS_READS
	rm -rf testpaths/ss4/NFS_READS