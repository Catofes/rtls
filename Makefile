all:
	mkdir -p build
	env GO111MODULE=on CGO_ENABLED=0 go build -o build/main .
	docker build --rm -t catofes/rtls .

upload-master:
	docker push catofes/rtls:latest

upload-tag:
	docker push catofes/rtls:"$(TRAVIS_TAG)"