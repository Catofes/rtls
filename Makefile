all:
	mkdir -p build
	env GO111MODULE=on CGO_ENABLED=0 go build -o build/main .

upload-master:
	docker push catofes/rtls tag=latest

upload-tag:
	docker push catofes/rtls tag="$(TRAVIS_TAG)"