package cliutil

import (
	"fmt"
	"os"
)

const helpText = `Usage:
  otp help
  otp genkey <key-file> <length-in-bytes>
  otp encipher <key-file> <message>
  otp decipher <key-file> <base64-ciphertext>

Commands:
  help       Show this help text
  genkey     Generate a random key and write it to the given key file
  encipher   Encrypt a message with the given key file and print base64 ciphertext
  decipher   Decrypt a base64 ciphertext with the given key file and print plaintext

Key bytes are consumed after each encipher/decipher operation. Do not run
multiple operations against the same key file concurrently.
`

func Die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func RequireMinArgs(args []string, min int, msg string) {
	if len(args) < min {
		Die(msg)
	}
}

func HelpText() string {
	return helpText
}

func PrintHelp() {
	fmt.Fprint(os.Stdout, helpText)
}
