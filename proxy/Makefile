all:
	docker build ~/oqs -t ccap24/oqs-nginx
	docker login
	docker tag ccap24/oqs-nginx ccap24/oqs-nginx:1.0
	docker push ccap24/oqs-nginx:1.0

