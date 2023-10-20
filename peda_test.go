package peda

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

func TestCreateNewUser(t *testing.T) {
	userdata := User{
		Username: "pakrolly",
		Password: "ganteng",
		Role:     "admin",
	}

	// You may want to create a connection to your MongoDB database and insert the user data here.
	// Replace the following code with your database operations.

	mconn := SetConnection("mongodb://raulgantengbanget:0nGCVlPPoCsXNhqG@ac-oilbpwk-shard-00-00.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-01.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-02.9ofhjs3.mongodb.net:27017/test?replicaSet=atlas-13x7kp-shard-0&ssl=true&authSource=admin", "petapedia")
	err := CreateNewUserRole(mconn, "user", userdata)
	if err != nil {
		t.Errorf("Error creating a new user: %v", err)
	}
	t.Logf("User created successfully: %s", userdata.Username)
}

func TestDeleteUser(t *testing.T) {

	mconn := SetConnection("mongodb://raulgantengbanget:0nGCVlPPoCsXNhqG@ac-oilbpwk-shard-00-00.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-01.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-02.9ofhjs3.mongodb.net:27017/test?replicaSet=atlas-13x7kp-shard-0&ssl=true&authSource=admin", "petapedia")
	var userdata User
	userdata.Username = "maulana"
	DeleteUser(mconn, "user", userdata)
}

func TestFindUser(t *testing.T) {
	var userdata User
	userdata.Username = "petped"
	mconn := SetConnection("mongodb://raulgantengbanget:0nGCVlPPoCsXNhqG@ac-oilbpwk-shard-00-00.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-01.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-02.9ofhjs3.mongodb.net:27017/test?replicaSet=atlas-13x7kp-shard-0&ssl=true&authSource=admin", "petapedia")
	res := FindUser(mconn, "user", userdata)
	fmt.Println(res)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "ganteng"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("bangsat", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("mongodb://raulgantengbanget:0nGCVlPPoCsXNhqG@ac-oilbpwk-shard-00-00.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-01.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-02.9ofhjs3.mongodb.net:27017/test?replicaSet=atlas-13x7kp-shard-0&ssl=true&authSource=admin", "petapedia")
	var userdata User
	userdata.Username = "bangsat"
	userdata.Password = "ganteng"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)

}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("mongodb://raulgantengbanget:0nGCVlPPoCsXNhqG@ac-oilbpwk-shard-00-00.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-01.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-02.9ofhjs3.mongodb.net:27017/test?replicaSet=atlas-13x7kp-shard-0&ssl=true&authSource=admin", "petapedia")
	var userdata User
	userdata.Username = "bangsat"
	userdata.Password = "ganteng"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}
