BASE_URL := https://agres.online/

build:
	cd blog && hugo --cleanDestinationDir --minify -b $(BASE_URL)

serve:
	cd blog && hugo serve -D --cleanDestinationDir --buildFuture

clean:
	cd blog && rm -rf ./public/*

.PHONY: build serve clean
