build:
	docker build -t ghcr.io/sbekti/smsproxy:latest .

push:
	docker push ghcr.io/sbekti/smsproxy:latest
