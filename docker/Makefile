build:
	docker build -t wireproxy .
	
run:
	docker run \
	--rm --tty --interactive \
	--name=wireproxy \
	--publish 2534:2534 \
	--volume "${PWD}/config:/etc/wireproxy/config:ro" \
	wireproxy