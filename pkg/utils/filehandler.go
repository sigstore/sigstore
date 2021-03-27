package utils

import (
	"github.com/gabriel-vasile/mimetype"
)

var SupportedFileTypes = map[string]struct{}{
	"text/plain; charset=utf-8": {},
	"application/jar": {},
	"application/x-bzip2": {},
	"application/x-tar": {},
	"application/x-gzip": {},
	"application/x-gunzip": {},
	"application/gzipped": {},
	"application/gzip-compressed": {},
	"application/x-gzip-compressed": {},
	"gzip/document": {},
}

func GetFileType(filename string) (string, error)  {
	mime, err := mimetype.DetectFile(filename)
	if err != nil {
		return "", err
	}
	return mime.String(), nil
}
