package peda

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/aiteung/atdb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CreateResponse(status bool, message string, data interface{}) Response {
	response := Response{
		Status:  status,
		Message: message,
		Data:    data,
	}
	return response
}

// pengecekantoken
func IsTokenValid(publickey, tokenstr string) (payload Payload, err error) {
	var token *paseto.Token
	var pubKey paseto.V4AsymmetricPublicKey
	pubKey, err = paseto.NewV4AsymmetricPublicKeyFromHex(publickey) // this wil fail if given key in an invalid format
	if err != nil {
		fmt.Println("Decode NewV4AsymmetricPublicKeyFromHex : ", err)
	}
	parser := paseto.NewParser()                             // only used because this example token has expired, use NewParser() (which checks expiry by default)
	token, err = parser.ParseV4Public(pubKey, tokenstr, nil) // this will fail if parsing failes, cryptographic checks fail, or validation rules fail
	if err != nil {
		fmt.Println("Decode ParseV4Public : ", err)
	} else {
		json.Unmarshal(token.ClaimsJSON(), &payload)
	}
	return payload, err
}

func GenerateKey() (privatekey, publickey string) {
	secretKey := paseto.NewV4AsymmetricSecretKey() // don't share this!!!
	privatekey = secretKey.ExportHex()             // DO share this one
	publickey = secretKey.Public().ExportHex()
	return privatekey, publickey
}

func Encode(name, username, role, privatekey string) (string, error) {
	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(2 * time.Hour))
	token.SetString("name", name)
	token.SetString("username", username)
	token.SetString("role", role)
	key, err := paseto.NewV4AsymmetricSecretKeyFromHex(privatekey)
	return token.V4Sign(key, nil), err
}

func SetConnection2dsphereTest(mongoenv, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: mongoenv,
		DBName:   dbname,
	}
	db := atdb.MongoConnect(DBmongoinfo)

	// Create a geospatial index if it doesn't exist
	indexModel := mongo.IndexModel{
		Keys: bson.D{
			{Key: "geometry", Value: "2dsphere"},
		},
	}

	_, err := db.Collection("near").Indexes().CreateOne(context.TODO(), indexModel)
	if err != nil {
		log.Printf("Error creating geospatial index: %v\n", err)
	}
	return db
}
