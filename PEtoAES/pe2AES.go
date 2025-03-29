package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	path := flag.String("p", "sample.exe", "path")
	key := flag.String("k", "12345678901234567890123456789012", "key for encryption")
	xorKey := flag.Int("x", 42, "XOR key (0-255) for additional encryption")
	flag.Parse()

	xorByte := byte(*xorKey)

	peToDoubleEncrypt(*path, *key, xorByte)
}

func peToAES(destPath string, key string) {
	if len(key) != 32 {
		fmt.Println("[-] The key needs to be 12 chars long")
		return
	}
	byteKey := []byte(key)
	destPE, err := ioutil.ReadFile(destPath)
	if err != nil {
		log.Fatal(err)
	}
	file1, err := os.Create("../pe.txt")

	defer file1.Close()

	hexPayload := hex.EncodeToString(destPE)
	aesPayload, _ := encrypt([]byte(hexPayload), byteKey)
	_, err = fmt.Fprintf(file1, "%s", aesPayload)

	file2, err := os.Create("../key.txt")

	defer file1.Close()

	_, err = fmt.Fprintf(file2, "%s", key)

	fmt.Println("[+] Done !")
}

func encrypt(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)

	cypherText := gcm.Seal(nonce, nonce, plainText, nil)
	return cypherText, nil
}
func peToDoubleEncrypt(destPath string, aesKey string, xorKey byte) {
	if len(aesKey) != 32 {
		fmt.Println("[-] The AES key needs to be 32 chars long")
		return
	}
	byteKey := []byte(aesKey)
	destPE, err := ioutil.ReadFile(destPath)
	if err != nil {
		log.Fatal(err)
	}

	hexPayload := hex.EncodeToString(destPE)

	xorPayload := make([]byte, len(hexPayload))
	for i := 0; i < len(hexPayload); i++ {
		xorPayload[i] = hexPayload[i] ^ xorKey
	}

	aesPayload, _ := encrypt(xorPayload, byteKey)

	file1, err := os.Create("../pe.txt")

	defer file1.Close()

	_, err = fmt.Fprintf(file1, "%s", aesPayload)

	file2, err := os.Create("../key.txt")

	defer file2.Close()

	_, err = fmt.Fprintf(file2, "%s:%d", aesKey, xorKey)

	fmt.Println("[+] Double encryption done!")
}
