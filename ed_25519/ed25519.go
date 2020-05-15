package ed_25519

import (
	"math/rand"
	"time"

	"github.com/onlyangel/apihandlers"
	"golang.org/x/crypto/ed25519"

	crypto "github.com/crypt0cloud/crypto_go"
)

func GetNewKeyPair() (string, string) {
	appPublicKey, appPrivateKey, err := ed25519.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	apihandlers.PanicIfNotNil(err)

	return crypto.Base64_encode(appPublicKey), crypto.Base64_encode(appPrivateKey)
}
