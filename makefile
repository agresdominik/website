BASE_URL := https://agres.online/
DEST := public
HUGO := hugo

build:
	cd blog && hugo --cleanDestinationDir --minify -b $(BASE_URL)

serve:
	cd blog && hugo serve -D --cleanDestinationDir

clean:
	cd blog && rm -rf ./public/* 

.PHONY: build serve clean


