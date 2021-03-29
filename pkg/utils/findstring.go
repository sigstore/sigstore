package utils

func FindString(s string) bool {
	if _, ok := SupportedFileTypes[s]; ok {
		return true
	}
	return false
}
