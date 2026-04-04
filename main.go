package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/adelos-labs/one-and-done/cliutil"
	"github.com/adelos-labs/one-and-done/keymanagement"
	"github.com/adelos-labs/one-and-done/onetimepad/metadata"
)

func main() {
	if len(os.Args) < 2 {
		cliutil.PrintHelp()
		return
	}

	switch os.Args[1] {
	case "help", "-h", "--help":
		cliutil.PrintHelp()
	case "encipher":
		cliutil.RequireMinArgs(os.Args, 4, "missing arguments for encipher\n\n"+cliutil.HelpText())
		encipher(os.Args[2], os.Args[3])
	case "decipher":
		cliutil.RequireMinArgs(os.Args, 4, "missing arguments for decipher\n\n"+cliutil.HelpText())
		decipher(os.Args[2], os.Args[3])
	case "genkey":
		cliutil.RequireMinArgs(os.Args, 4, "missing arguments for genkey\n\n"+cliutil.HelpText())
		genkey(os.Args[2], os.Args[3])
	default:
		cliutil.Die("unknown command: %s\n\n%s", os.Args[1], cliutil.HelpText())
	}
}

func encipher(keyFile, message string) {
	plaintext := []byte(message)

	keyLen, cipher, remaining, err := metadata.Encipher(keyFile, plaintext)
	if err != nil {
		cliutil.Die("%v", err)
	}

	fmt.Printf("%d:%s\n", keyLen, base64.StdEncoding.EncodeToString(cipher))
	printKeyStatus(keyFile, remaining)
}

func decipher(keyFile, encoded string) {
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		cliutil.Die("invalid message format: expected keylen:base64")
	}

	keyLen, err := strconv.Atoi(parts[0])
	if err != nil {
		cliutil.Die("invalid key length %q: %v", parts[0], err)
	}

	cipher, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		cliutil.Die("invalid base64: %v", err)
	}

	plaintext, remaining, err := metadata.Decipher(keyFile, keyLen, cipher)
	if err != nil {
		cliutil.Die("%v", err)
	}

	fmt.Println(string(plaintext))
	printKeyStatus(keyFile, remaining)
}

func printKeyStatus(keyFile string, remaining int) {
	if remaining == 0 {
		fmt.Fprintf(os.Stderr, "key fully consumed, key file removed: %s\n", keyFile)
	} else {
		fmt.Fprintf(os.Stderr, "%d key bytes remaining in %s\n", remaining, keyFile)
	}
}

func genkey(keyFile, lengthStr string) {
	length, err := strconv.Atoi(lengthStr)
	if err != nil || length <= 0 {
		cliutil.Die("length must be a positive integer")
	}

	key, err := keymanagement.GenKey(length)
	if err != nil {
		cliutil.Die("error generating key: %v", err)
	}

	if err := keymanagement.WriteKey(keyFile, key); err != nil {
		if errors.Is(err, keymanagement.ErrKeyExists) {
			cliutil.Die("key file already exists, refusing to overwrite: %s", keyFile)
		}
		cliutil.Die("error writing key file: %v", err)
	}

	fmt.Fprintf(os.Stderr, "wrote %d-byte key to %s\n", length, keyFile)
}
