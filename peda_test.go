package peda

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

// func TestUpdateGetData(t *testing.T) {
// 	mconn := SetConnection("MONGOULBI", "petapedia")
// 	datagedung := GetAllUser(mconn, "user")
// 	fmt.Println(datagedung)
// }

// }
// func TestGCFCreateHandler(t *testing.T) {
// 	// Simulate input parameters
// 	MONGOCONNSTRINGENV := "mongodb://raulgantengbanget:0nGCVlPPoCsXNhqG@ac-oilbpwk-shard-00-00.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-01.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-02.9ofhjs3.mongodb.net:27017/test?replicaSet=atlas-13x7kp-shard-0&ssl=true&authSource=admin"
// 	dbname := "petapedia"
// 	collectionname := "user"

// 	// Create a test User
// 	datauser := User{
// 		Username: "testuser",
// 		Password: "testpassword",
// 		Role:     "user",
// 	}

//		// Call the handler function
//		result := GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname, datauser)
//		fmt.Println(result)
//		// You can add assertions here to validate the result, or check the database for the created user.
//	}
func TestUpdateGetData(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	datagedung := GetAllBangunanLineString(mconn, "petapedia")
	fmt.Println(datagedung)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "admin123"
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
	hasil, err := watoken.Encode("admin123", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "proyek3")
	var userdata User
	userdata.Username = "rolly"
	userdata.Password = "admin123"
	userdata.Role = "admin"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "dosen", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)

}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata User
	userdata.Username = "petped"
	userdata.Password = "secret"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Username = "raulmahya"
	userdata.Password = "banget"
	userdata.Role = "admin"
	mconn := SetConnection("MONGOULBI", "petapedia")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestDeleteUser(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata User
	userdata.Username = "yyy"
	DeleteUser(mconn, "user", userdata)
}

func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Username = "raulmahya"
	userdata.Password = "banget"
	userdata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOULBI", "petapedia")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata User
	userdata.Username = "raulmahya"
	userdata.Password = "banget"
	userdata.Role = "admin"
	CreateNewUserRole(mconn, "user", userdata)
}

func TestAllProduct(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	product := GetAllProduct(mconn, "product")
	fmt.Println(product)
}

func CreateContent(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var contentdata Content
	contentdata.ID = 1
	contentdata.Content = "raul"
	contentdata.Description = "mahya"
	contentdata.Image = "https://images3.alphacoders.com/165/thumb-1920-165265.jpg"
	CreateNewContent(mconn, "content", contentdata)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata User
	userdata.Username = "raulmahya"
	userdata.Password = "banget"
	userdata.Role = "admin"
	CreateUser(mconn, "user", userdata)
}

func TestLoginn(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata User
	userdata.Username = "pokpokpokpok123"
	userdata.Password = "pokpokpokpok123"
	IsPasswordValid(mconn, "user", userdata)
	fmt.Println(userdata)
}

func TestTing(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata Testing
	userdata.ID = 1
	userdata.Title = "raul"
	userdata.Description = "mahya"
	userdata.Image = "https://images3.alphacoders.com/165/thumb-1920-165265.jpg"
	userdata.Status = true
	userdata.Nama = "raul"
	userdata.alamat = "mahya"
	PostTesting(mconn, "testing", userdata)
	fmt.Println(userdata)
}

func TestTingUpdated(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata Testing
	userdata.ID = 1
	userdata.Title = "raul"
	userdata.Description = "mahya"
	userdata.Image = "https://images3.alphacoders.com/165/thumb-1920-165265.jpg"
	userdata.Status = true
	userdata.Nama = "raul"
	userdata.alamat = "mahya"
	DeleteTesting(mconn, "testing", userdata)
	fmt.Println(userdata)
}

func TestTingLogin(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata User
	userdata.Username = "asdasdasd"
	userdata.Password = "testing1asdglaskudgfashjdfashgdfasf23"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
	fmt.Println(userdata)
}

func TestPrivateToken(t *testing.T) {
	mconn := SetConnection("MONGOULBI", "petapedia")
	var userdata User
	userdata.Private = "0d6146d421b512a59a70c22ab65023b70a4a64fec0e28db60b79f77dfa459a2948b259cac361a19e5c98eefeaf3262fae7f06a837e094caf5ee97f8de5b9c069"

	result := FindPrivate(mconn, "user", userdata)

	fmt.Println(result)
}

func TestUsername(t *testing.T) {
	var userdata User
	userdata.Username = "6281312000300"
	userdata.Password = "admin123"
	usernameExists("mongodb+srv://workfield2308:SLKltAPVArpJeAyk@cluster0.wfrms4g.mongodb.net/", "dosen", userdata)
	fmt.Println(userdata)
}

func TestUpdateGetDataa(t *testing.T) {
	mconn := SetConnection("mongoenv", "petapedia")
	datagedung := GeoIntersects(mconn, 103.61061534308766, -1.6272725906014358)
	fmt.Println(datagedung)
}
func TestGeoWithin(t *testing.T) {
	mconn := SetConnection("mongodb+srv://raulgantengbanget:0nGCVlPPoCsXNhqG@cluster0.9ofhjs3.mongodb.net/?retryWrites=true&w=majority", "petapediaaa")
	coordinates := [][][]float64{
		{
			{103.62052506248301,
				-1.6105001000148462},
			{103.62061804929925,
				-1.6106710617710007},
			{103.62071435707355,
				-1.6106229269090022},
			{103.62061472834131,
				-1.6104420062116702},
			{103.62052506248301,
				-1.6105001000148462},
		},
	}

	datagedung := GeoWithin(mconn, coordinates)
	fmt.Println(datagedung)
}

// func TestNear(t *testing.T) {
// 	mconn := SetConnection2dsphereTest("mongoenv", "petapediaaa")
// 	datagedung := Near(mconn, 103.61028753823456, -1.6246312350403684)
// 	fmt.Println(datagedung)
// }

// func TestNearSphere(t *testing.T) {
// 	mconn := SetConnection2dsphereTest("mongoenv", "petapediaaa")
// 	datagedung := NearSpehere(mconn, 103.61028753823456, -1.6246312350403684)
// 	fmt.Println(datagedung)
// }
