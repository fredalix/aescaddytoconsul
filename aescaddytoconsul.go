package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/pteich/errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

const fileExtension = ".encrypted"
const aesKey = "consultls-1234567890-caddytls-32"

type FileData struct {
	Path string
	Data []byte
}

func main() {
	// Récupération de la clé de chiffrement
	key := []byte(aesKey)
	if len(key) != 32 {
		panic("La clé de chiffrement doit contenir 32 caractères")
	}

	// Parcours récursif du répertoire
	rootDir := "/tmp/gonsul/repo"
	var files []FileData
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		fmt.Printf("Lecture du fichier %s\n", path)
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return errors.Wrap(err, "erreur lors de la lecture du fichier "+path)
		}
		files = append(files, FileData{Path: path, Data: data})
		return nil
	})
	if err != nil {
		panic(err)
	}

	// Encodage en JSON et chiffrement des fichiers
	for _, file := range files {
		fmt.Printf("Encodage JSON et chiffrement du fichier %s\n", file.Path)
		data, err := json.Marshal(file)
		if err != nil {
			panic(errors.Wrap(err, "erreur lors de l'encodage JSON du fichier "+file.Path))
		}
		encryptedData, err := encrypt(data, key)
		if err != nil {
			panic(errors.Wrap(err, "erreur lors du chiffrement du fichier "+file.Path))
		}
		newFilePath := file.Path + fileExtension
		fmt.Printf("Ecriture du fichier chiffré %s\n", newFilePath)
		err = ioutil.WriteFile(newFilePath, encryptedData, 0644)
		if err != nil {
			panic(errors.Wrap(err, "erreur lors de l'écriture du fichier chiffré "+newFilePath))
		}
		fmt.Printf("Effacement du fichier original %s\n", file.Path)
		err = os.Remove(file.Path)
		if err != nil {
			panic(errors.Wrap(err, "erreur lors de la suppression du fichier original "+file.Path))
		}
	}
}

func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "impossible de créer le chiffreur AES")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "impossible de créer le chiffreur GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "impossible de générer un nonce aléatoire")
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}
