package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type ETHWallet struct {
	PublicKey       []byte
	PrivateKey      []byte
	Address         string
	Alias           string
	ecdsaPrivateKey *ecdsa.PrivateKey
}

var ETHWallets map[string]*ETHWallet

func MakeWallet(Alias string) *ETHWallet {
	PrivateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	PrivateKeyBytes := crypto.FromECDSA(PrivateKey)
	fmt.Println("private key :", hexutil.Encode(PrivateKeyBytes)[4:])
	PublicKey := PrivateKey.Public()
	PublicKeyECDSA, ok := PublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Cannot assert type :PublicKey is not of type *ecdsa.PublicKey")
	}
	PublicKeyBytes := crypto.FromECDSAPub(PublicKeyECDSA)
	fmt.Println("public key :", hexutil.Encode(PublicKeyBytes)[4:])

	address := crypto.PubkeyToAddress(*PublicKeyECDSA).Hex()
	fmt.Println("address :", address)
	Wallet := new(ETHWallet)
	Wallet.Address = address
	Wallet.Alias = Alias
	Wallet.PublicKey = PublicKeyBytes
	Wallet.PrivateKey = PrivateKeyBytes
	Wallet.ecdsaPrivateKey = PrivateKey
	return Wallet
}

func Signature(Address string, Hash []byte) string {
	wallet := ETHWallets[Address]
	Answer := ""
	if wallet != nil {
		SignValue, _ := ecdsa.SignASN1(rand.Reader, wallet.ecdsaPrivateKey, Hash)
		if Verify(Address, Hash, SignValue) {
			Answer = "1"
		} else {
			Answer = "0"
		}
		return Answer
	} else {
		Answer = "-1"
		return Answer
	}

}

func Verify(Address string, Hash []byte, SignValue []byte) bool {
	wallet := ETHWallets[Address]

	return ecdsa.VerifyASN1(&wallet.ecdsaPrivateKey.PublicKey, Hash, SignValue)
}
