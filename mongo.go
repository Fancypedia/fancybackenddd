package peda

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

func GetAllBangunanLineString(mongoconn *mongo.Database, collection string) []GeoJson {
	lokasi := atdb.GetAllDoc[[]GeoJson](mongoconn, collection)
	return lokasi
}

func CreateUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	userid := userdata.Username
	tokenstring, err := watoken.Encode(userid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get userid
	useridstring := watoken.DecodeGetId(publicKey, tokenstring)
	if useridstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(useridstring)
	userdata.Private = privateKey
	userdata.Publick = publicKey
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func GetAllProduct(mongoconn *mongo.Database, collection string) []Product {
	product := atdb.GetAllDoc[[]Product](mongoconn, collection)
	return product
}

func GetNameAndPassowrd(mongoconn *mongo.Database, collection string) []User {
	user := atdb.GetAllDoc[[]User](mongoconn, collection)
	return user
}

func GetAllContent(mongoconn *mongo.Database, collection string) []Content {
	content := atdb.GetAllDoc[[]Content](mongoconn, collection)
	return content
}

//	func GetAllUser(mongoconn *mongo.Database, collection string) []User {
//		user := atdb.GetAllDoc[[]User](mongoconn, collection)
//		return user
//	}
func CreateNewUserRole(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}
func CreateUserAndAddedToeken(PASETOPRIVATEKEYENV string, mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	atdb.InsertOneDoc(mongoconn, collection, userdata)

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Update the user data in the database
	return atdb.ReplaceOneDoc(mongoconn, collection, bson.M{"username": userdata.Username}, userdata)
}

func DeleteUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	filter := bson.M{"username": userdata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}
func ReplaceOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, userdata User) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, userdata)
}
func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindUserUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{
		"username": userdata.Username,
	}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindUserUserr(mongoconn *mongo.Database, collection string, userdata User) (User, error) {
	filter := bson.M{
		"username": userdata.Username,
	}

	var user User
	err := mongoconn.Collection(collection).FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CheckPasswordHash(userdata.Password, res.Password)
}

// product

func CreateNewProduct(mongoconn *mongo.Database, collection string, productdata Product) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, productdata)
}

// content
func CreateNewContent(mongoconn *mongo.Database, collection string, contentdata Content) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, contentdata)
}

func DeleteContent(mongoconn *mongo.Database, collection string, contentdata Content) interface{} {
	filter := bson.M{"id": contentdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func ReplaceContent(mongoconn *mongo.Database, collection string, filter bson.M, contentdata Content) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, contentdata)
}

func CreateNewBlog(mongoconn *mongo.Database, collection string, blogdata Blog) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, blogdata)
}

func FindContentAllId(mongoconn *mongo.Database, collection string, contentdata Content) Content {
	filter := bson.M{"id": contentdata.ID}
	return atdb.GetOneDoc[Content](mongoconn, collection, filter)
}

func GetAllBlogAll(mongoconn *mongo.Database, collection string) []Blog {
	blog := atdb.GetAllDoc[[]Blog](mongoconn, collection)
	return blog
}

func GetIDBlog(mongoconn *mongo.Database, collection string, blogdata Blog) Blog {
	filter := bson.M{"id": blogdata.ID}
	return atdb.GetOneDoc[Blog](mongoconn, collection, filter)
}

func CreateUserAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) error {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	userdata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, userdata.Username); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

func AuthenticateUserAndGenerateToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) (string, error) {
	// Cari pengguna berdasarkan nama pengguna
	username := userdata.Username
	password := userdata.Password
	userdata, err := FindUserByUsername(mongoconn, collection, username)
	if err != nil {
		return "", err
	}

	// Memeriksa kata sandi
	if !CheckPasswordHash(password, userdata.Password) {
		return "", errors.New("Password salah") // Gantilah pesan kesalahan sesuai kebutuhan Anda
	}

	// Generate token untuk otentikasi
	tokenstring, err := watoken.Encode(username, os.Getenv(privateKeyEnv))
	if err != nil {
		return "", err
	}

	return tokenstring, nil
}

func FindUserByUsername(mongoconn *mongo.Database, collection string, username string) (User, error) {
	var user User
	filter := bson.M{"username": username}
	err := mongoconn.Collection(collection).FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// create login using Private
func CreateLogin(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword
	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, userdata.Private)
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func CreateComment(mongoconn *mongo.Database, collection string, commentdata Comment) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, commentdata)
}

func DeleteComment(mongoconn *mongo.Database, collection string, commentdata Comment) interface{} {
	filter := bson.M{"id": commentdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedComment(mongoconn *mongo.Database, collection string, filter bson.M, commentdata Comment) interface{} {
	filter = bson.M{"id": commentdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, commentdata)
}

func GetAllComment(mongoconn *mongo.Database, collection string) []Comment {
	comment := atdb.GetAllDoc[[]Comment](mongoconn, collection)
	return comment
}

// event global function

func CreateEventGlobal(mongoconn *mongo.Database, collection string, eventglobaldata EventGlobal) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, eventglobaldata)
}

func DeleteEventGlobal(mongoconn *mongo.Database, collection string, eventglobaldata EventGlobal) interface{} {
	filter := bson.M{"id": eventglobaldata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedEventGlobal(mongoconn *mongo.Database, collection string, filter bson.M, eventglobaldata EventGlobal) interface{} {
	filter = bson.M{"id": eventglobaldata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, eventglobaldata)
}

func GetAllEventGlobal(mongoconn *mongo.Database, collection string) []EventGlobal {
	eventglobal := atdb.GetAllDoc[[]EventGlobal](mongoconn, collection)
	return eventglobal
}

func GetAllEventGlobalId(mongoconn *mongo.Database, collection string, eventglobaldata EventGlobal) []EventGlobal {
	filter := bson.M{"id": eventglobaldata.ID}
	eventglobal := atdb.GetOneDoc[[]EventGlobal](mongoconn, collection, filter)
	return eventglobal
}

// event function

func CreateEvent(mongoconn *mongo.Database, collection string, eventdata Event) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, eventdata)
}

func DeleteEvent(mongoconn *mongo.Database, collection string, eventdata Event) interface{} {
	filter := bson.M{"id": eventdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedEvent(mongoconn *mongo.Database, collection string, filter bson.M, eventdata Event) interface{} {
	filter = bson.M{"id": eventdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, eventdata)
}

func GetAllEvent(mongoconn *mongo.Database, collection string) []Event {
	event := atdb.GetAllDoc[[]Event](mongoconn, collection)
	return event
}

func GetIDEvent(mongoconn *mongo.Database, collection string, eventdata Event) Event {
	filter := bson.M{"id": eventdata.ID}
	return atdb.GetOneDoc[Event](mongoconn, collection, filter)
}

// about function

func CreateAbout(mongoconn *mongo.Database, collection string, aboutdata About) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, aboutdata)
}

func DeleteAbout(mongoconn *mongo.Database, collection string, aboutdata About) interface{} {
	filter := bson.M{"id": aboutdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedAbout(mongoconn *mongo.Database, collection string, filter bson.M, aboutdata About) interface{} {
	filter = bson.M{"id": aboutdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, aboutdata)
}

func GetAllAbout(mongoconn *mongo.Database, collection string) []About {
	about := atdb.GetAllDoc[[]About](mongoconn, collection)
	return about
}

func GetIDAbout(mongoconn *mongo.Database, collection string, aboutdata About) About {
	filter := bson.M{"id": aboutdata.ID}
	return atdb.GetOneDoc[About](mongoconn, collection, filter)
}

// gallery function

func CreateGallery(mongoconn *mongo.Database, collection string, gallerydata Gallery) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, gallerydata)
}

func DeleteGallery(mongoconn *mongo.Database, collection string, gallerydata Gallery) interface{} {
	filter := bson.M{"id": gallerydata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedGallery(mongoconn *mongo.Database, collection string, filter bson.M, gallerydata Gallery) interface{} {
	filter = bson.M{"id": gallerydata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, gallerydata)
}

func GetAllGallery(mongoconn *mongo.Database, collection string) []Gallery {
	gallery := atdb.GetAllDoc[[]Gallery](mongoconn, collection)
	return gallery
}

func GetIDGallery(mongoconn *mongo.Database, collection string, gallerydata Gallery) Gallery {
	filter := bson.M{"id": gallerydata.ID}
	return atdb.GetOneDoc[Gallery](mongoconn, collection, filter)
}

// contact function

func CreateContact(mongoconn *mongo.Database, collection string, contactdata Contack) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, contactdata)
}

func DeleteContact(mongoconn *mongo.Database, collection string, contactdata Contack) interface{} {
	filter := bson.M{"id": contactdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedContact(mongoconn *mongo.Database, collection string, filter bson.M, contactdata Contack) interface{} {
	filter = bson.M{"id": contactdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, contactdata)
}

func GetAllContact(mongoconn *mongo.Database, collection string) []Contack {
	contact := atdb.GetAllDoc[[]Contack](mongoconn, collection)
	return contact
}

func GetIdContact(mongoconn *mongo.Database, collection string, contactdata Contack) Contack {
	filter := bson.M{"id": contactdata.ID}
	return atdb.GetOneDoc[Contack](mongoconn, collection, filter)
}

// CreateIklan function
func CreateIklan(mongoconn *mongo.Database, collection string, iklandata Iklan) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, iklandata)
}

func DeleteIklan(mongoconn *mongo.Database, collection string, iklandata Iklan) interface{} {
	filter := bson.M{"id": iklandata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedIklan(mongoconn *mongo.Database, collection string, filter bson.M, iklandata Iklan) interface{} {
	filter = bson.M{"id": iklandata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, iklandata)
}

func GetAllIklan(mongoconn *mongo.Database, collection string) []Iklan {
	iklan := atdb.GetAllDoc[[]Iklan](mongoconn, collection)
	return iklan
}

func GetIDIklan(mongoconn *mongo.Database, collection string, iklandata Iklan) Iklan {
	filter := bson.M{"id": iklandata.ID}
	return atdb.GetOneDoc[Iklan](mongoconn, collection, filter)
}

// gis function

func PostLinestring(mongoconn *mongo.Database, collection string, linestringdata GeoJsonLineString) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, linestringdata)
}

func GetByCoordinate(mongoconn *mongo.Database, collection string, linestringdata GeoJsonLineString) GeoJsonLineString {
	filter := bson.M{"geometry.coordinates": linestringdata.Geometry.Coordinates}
	return atdb.GetOneDoc[GeoJsonLineString](mongoconn, collection, filter)
}
