package peda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"os"
	"strings"
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func FindallProduct(mconn *mongo.Database, collname string) []Product {
	salon := atdb.GetAllDoc[[]Product](mconn, collname)
	return salon
}

func FindallContent(mconn *mongo.Database, collname string) []Content {
	salon := atdb.GetAllDoc[[]Content](mconn, collname)
	return salon
}

func DecodeGetName(publickey string, tokenstring string) string {
	payload, err := Decode(publickey, tokenstring)
	if err != nil {
		fmt.Println("Decode DecodeGetId : ", err)
	}
	return payload.Name
}

func DecodeGetUsername(publickey string, tokenstring string) string {
	payload, err := Decode(publickey, tokenstring)
	if err != nil {
		fmt.Println("Decode DecodeGetId : ", err)
	}
	return payload.Username
}

func DecodeGetRole(publickey string, tokenstring string) string {
	payload, err := Decode(publickey, tokenstring)
	if err != nil {
		fmt.Println("Decode DecodeGetId : ", err)
	}
	return payload.Role
}
func DecodeGetNomor(publickey string, tokenstring string) string {
	payload, err := Decode(publickey, tokenstring)
	if err != nil {
		fmt.Println("Decode DecodeGetId : ", err)
	}
	return payload.Nomor
}

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

func FindUserByPrivate(mongoconn *mongo.Database, collection string, userdata User) (User, error) {
	var user User
	filter := bson.M{"private": userdata.Private}
	err := mongoconn.Collection(collection).FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func GetAllProduct(mongoconn *mongo.Database, collection string) []Product {
	product := atdb.GetAllDoc[[]Product](mongoconn, collection)
	return product
}

func GetAllSidang(mongoconn *mongo.Database, collection string) []InputSidang {
	sidang := atdb.GetAllDoc[[]InputSidang](mongoconn, collection)
	return sidang
}

func CreateSidang(mongoconn *mongo.Database, collection string, sidangdata InputSidang) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, sidangdata)
}

func UpdateSidang(mongoconn *mongo.Database, collection string, filter bson.M, sidangdata InputSidang) interface{} {
	filter = bson.M{"id": sidangdata.Npm}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, sidangdata)
}

func DeleteSidang(mongoconn *mongo.Database, collection string, sidangdata InputSidang) interface{} {
	filter := bson.M{"id": sidangdata.Npm}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)

}

func GetAllFrontend(mongoconn *mongo.Database, collection string) []Frontend {
	sidang := atdb.GetAllDoc[[]Frontend](mongoconn, collection)
	return sidang
}

func CreateFronent(mongoconn *mongo.Database, collection string, sidangdata Frontend) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, sidangdata)
}

func UpdateFrontend(mongoconn *mongo.Database, collection string, filter bson.M, sidangdata Frontend) interface{} {
	filter = bson.M{"npm": sidangdata.Npm}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, sidangdata)
}

func DeleteFrondent(mongoconn *mongo.Database, collection string, sidangdata Frontend) interface{} {
	filter := bson.M{"npm": sidangdata.Npm}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func GetAllBackend(mongoconn *mongo.Database, collection string) []Backend {
	sidang := atdb.GetAllDoc[[]Backend](mongoconn, collection)
	return sidang
}
func GetallFrontend(mongoconn *mongo.Database, collection string) []Frontend {
	sidang := atdb.GetAllDoc[[]Frontend](mongoconn, collection)
	return sidang
}

func CreateBackend(mongoconn *mongo.Database, collection string, sidangdata Backend) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, sidangdata)
}

func UpdateBackend(mongoconn *mongo.Database, collection string, filter bson.M, sidangdata Backend) interface{} {
	filter = bson.M{"npm": sidangdata.Npm}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, sidangdata)
}

func DeleteBackend(mongoconn *mongo.Database, collection string, sidangdata Backend) interface{} {
	filter := bson.M{"npm": sidangdata.Npm}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func GetNameAndPassowrd(mongoconn *mongo.Database, collection string) []User {
	user := atdb.GetAllDoc[[]User](mongoconn, collection)
	return user
}

func GetAllContent(mongoconn *mongo.Database, collection string) []Content {
	content := atdb.GetAllDoc[[]Content](mongoconn, collection)
	return content
}
func GetAllUser(mongoconn *mongo.Database, collection string) []User {
	user := atdb.GetAllDoc[[]User](mongoconn, collection)
	return user
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
func usernameExists(mongoenv, dbname string, userdata User) bool {
	mconn := SetConnection(mongoenv, dbname).Collection("dosen")
	filter := bson.M{"notelp": userdata.Username}

	var user User
	err := mconn.FindOne(context.Background(), filter).Decode(&user)
	return err == nil
}

func InsertUserdata(mongoconn *mongo.Database, collname, username, password, no_whatsapp string) (InsertedID interface{}) {
	req := new(User)
	req.Username = username
	req.Password = password
	req.No_whatsapp = no_whatsapp
	return atdb.InsertOneDoc(mongoconn, collname, req)
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
	filter := bson.M{"notelp": userdata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}
func ReplaceOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, userdata User) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, userdata)
}
func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"notelp": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}
func FindUserByname(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindFrontend(mongoconn *mongo.Database, collection string, userdata Frontend) Frontend {
	filter := bson.M{"npm": userdata.Npm}
	return atdb.GetOneDoc[Frontend](mongoconn, collection, filter)
}

func FindBackend(mongoconn *mongo.Database, collection string, userdata Backend) Backend {
	filter := bson.M{"npm": userdata.Npm}
	return atdb.GetOneDoc[Backend](mongoconn, collection, filter)
}

func FindUserUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{
		"username": userdata.Username,
	}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}
func Decode(publickey, tokenstr string) (payload Payload, err error) {
	var token *paseto.Token
	var pubKey paseto.V4AsymmetricPublicKey

	// Pastikan bahwa kunci publik dalam format heksadesimal yang benar
	pubKey, err = paseto.NewV4AsymmetricPublicKeyFromHex(publickey)
	if err != nil {
		return payload, fmt.Errorf("failed to create public key: %s", err)
	}

	parser := paseto.NewParser()

	// Pastikan bahwa token memiliki format yang benar
	token, err = parser.ParseV4Public(pubKey, tokenstr, nil)
	if err != nil {
		return payload, fmt.Errorf("failed to parse token: %s", err)
	} else {
		// Handle token claims
		json.Unmarshal(token.ClaimsJSON(), &payload)
	}

	return payload, nil
}
func InsertUser(mconn *mongo.Database, collname string, datauser User) interface{} {
	return atdb.InsertOneDoc(mconn, collname, datauser)
}
func UsernameExists(mongoenvkatalogfilm, dbname string, userdata User) bool {
	mconn := SetConnection(mongoenvkatalogfilm, dbname).Collection("user")
	filter := bson.M{"username": userdata.Username}

	var user User
	err := mconn.FindOne(context.Background(), filter).Decode(&user)
	return err == nil
}

func FindPrivate(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{
		"private": userdata.Private,
	}

	var result User

	// Use the FindOne method to retrieve a single document
	err := mongoconn.Collection(collection).FindOne(context.TODO(), filter).Decode(&result)
	//resulnya hanya nama saja
	result = User{
		Username: result.Username,
	}

	if err != nil {
		log.Printf("Error finding user: %v\n", err)
		return User{}
	}

	return result
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

func IsPasswordValidd(mconn *mongo.Database, collection string, userdata User) (User, bool) {
	filter := bson.M{"username": userdata.Username}
	var foundUser User
	err := mconn.Collection(collection).FindOne(context.Background(), filter).Decode(&foundUser)
	if err != nil {
		return User{}, false
	}
	// Verify password here
	if CheckPasswordHash(userdata.Password, foundUser.Password) {
		return foundUser, true
	}
	return User{}, false
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

// product function
func CreateProduct(mongoconn *mongo.Database, collection string, productdata Product) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, productdata)
}

func DeleteProduct(mongoconn *mongo.Database, collection string, productdata Product) interface{} {
	filter := bson.M{"nomorid": productdata.Nomorid}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedProduct(mongoconn *mongo.Database, collection string, filter bson.M, productdata Product) interface{} {
	filter = bson.M{"nomorid": productdata.Nomorid}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, productdata)
}
func UpdateSidangFix(mongoconn *mongo.Database, collection string, filter bson.M, inputsidang Product) interface{} {
	filter = bson.M{"nomorid": inputsidang.Nomorid}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, inputsidang)
}

func GetAllProductt(mongoconn *mongo.Database, collection string) []Product {
	product := atdb.GetAllDoc[[]Product](mongoconn, collection)
	return product
}

func GetAllProductID(mongoconn *mongo.Database, collection string, productdata Product) Product {
	filter := bson.M{
		"nomorid":     productdata.Nomorid,
		"name":        productdata.Name,
		"description": productdata.Description,
		"price":       productdata.Price,
		"size":        productdata.Size,
		"stock":       productdata.Stock,
		"image":       productdata.Image,
	}
	productID := atdb.GetOneDoc[Product](mongoconn, collection, filter)
	return productID
}

// content function

func UpdatedProductt(mconn *mongo.Database, collname string, datasalon Product) interface{} {
	filterr := bson.M{"nomorid": datasalon.Nomorid}
	return atdb.ReplaceOneDoc(mconn, collname, filterr, datasalon)
}

func CreateContentt(mongoconn *mongo.Database, collection string, contentdata Content) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, contentdata)
}

func DeleteContentt(mongoconn *mongo.Database, collection string, contentdata Content) interface{} {
	filter := bson.M{"id": contentdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedContentt(mongoconn *mongo.Database, collection string, contentdata Content) interface{} {
	filter := bson.M{"id": contentdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, contentdata)
}

func GetAllContentt(mongoconn *mongo.Database, collection string) []Content {
	content := atdb.GetAllDoc[[]Content](mongoconn, collection)
	return content
}

func GetIDContentt(mongoconn *mongo.Database, collection string, contentdata Content) Content {
	filter := bson.M{"id": contentdata.ID}
	return atdb.GetOneDoc[Content](mongoconn, collection, filter)
}

// blog function
func CreateBlog(mongoconn *mongo.Database, collection string, blogdata Blog) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, blogdata)
}

func DeleteBlog(mongoconn *mongo.Database, collection string, blogdata Blog) interface{} {
	filter := bson.M{"id": blogdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedBlog(mongoconn *mongo.Database, collection string, filter bson.M, blogdata Blog) interface{} {
	filter = bson.M{"id": blogdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, blogdata)
}

func GetAllBlog(mongoconn *mongo.Database, collection string) []Blog {
	blog := atdb.GetAllDoc[[]Blog](mongoconn, collection)
	return blog
}

func GetIDBloggg(mongoconn *mongo.Database, collection string, blogdata Blog) Blog {
	filter := bson.M{"id": blogdata.ID}
	Blog := atdb.GetOneDoc[Blog](mongoconn, collection, filter)
	return Blog
}

// comment function
func CreateComment(mongoconn *mongo.Database, collection string, commentdata Comment) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, commentdata)
}

func DeleteComment(mongoconn *mongo.Database, collection string, commentdata Comment) interface{} {
	filter := bson.M{"id": commentdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedComment(mongoconn *mongo.Database, collection string, commentdata Comment) interface{} {
	filter := bson.M{"id": commentdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, commentdata)
}

func GetAllComment(mongoconn *mongo.Database, collection string) []Comment {
	comment := atdb.GetAllDoc[[]Comment](mongoconn, collection)
	return comment
}

func GetIDComment(mongoconn *mongo.Database, collection string, commentdata Comment) Comment {
	filter := bson.M{"id": commentdata.ID}
	return atdb.GetOneDoc[Comment](mongoconn, collection, filter)
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

func PostPolygone(mongoconn *mongo.Database, collection string, polygonedata GeoJsonPolygon) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, polygonedata)
}

func PostPoint(mongoconn *mongo.Database, collection string, pointdata GeometryPoint) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, pointdata)
}

func GetByCoordinate(mongoconn *mongo.Database, collection string, linestringdata GeoJsonLineString) GeoJsonLineString {
	filter := bson.M{"geometry.coordinates": linestringdata.Geometry.Coordinates}
	return atdb.GetOneDoc[GeoJsonLineString](mongoconn, collection, filter)
}

// delete gis
func DeleteLinestring(mongoconn *mongo.Database, collection string, linestringdata GeoJsonLineString) interface{} {
	filter := bson.M{"geometry.coordinates": linestringdata.Geometry.Coordinates}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedLinestring(mongoconn *mongo.Database, collection string, filter bson.M, linestringdata GeoJsonLineString) interface{} {
	filter = bson.M{"geometry.coordinates": linestringdata.Geometry.Coordinates}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, linestringdata)
}

func PostLocation(mongoconn *mongo.Database, collection string, locationdata Location) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, locationdata)
}

// testing crud
func PostTesting(mongoconn *mongo.Database, collection string, testingdata Testing) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, testingdata)
}

func DeleteTesting(mongoconn *mongo.Database, collection string, testingdata Testing) interface{} {
	filter := bson.M{"id": testingdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedTesting(mongoconn *mongo.Database, collection string, filter bson.M, testingdata Testing) interface{} {
	filter = bson.M{"id": testingdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, testingdata)
}

func GetAllTesting(mongoconn *mongo.Database, collection string) []Testing {
	testing := atdb.GetAllDoc[[]Testing](mongoconn, collection)
	return testing
}

func GeoIntersects(mongoconn *mongo.Database, long float64, lat float64) (namalokasi string) {
	lokasicollection := mongoconn.Collection("petapedia")
	filter := bson.M{
		"geometry": bson.M{
			"$geoIntersects": bson.M{
				"$geometry": bson.M{
					"type":        "Point",
					"coordinates": []float64{long, lat},
				},
			},
		},
	}
	var lokasi Lokasi
	err := lokasicollection.FindOne(context.TODO(), filter).Decode(&lokasi)
	if err != nil {
		fmt.Printf("GetLokasi: %v\n", err)
	}
	return lokasi.Properties.Name
}

func TestPolygon(t *testing.T) {
	// Set up MongoDB connection for testing
	mconn := SetConnection("mongodb+srv://raulgantengbanget:0nGCVlPPoCsXNhqG@cluster0.9ofhjs3.mongodb.net/?retryWrites=true&w=majority", "petapediaaa")

	// Example coordinates for a polygon
	coordinates := [][][]float64{
		{
			{103.62052506248301, -1.6105001000148462},
			{103.62061804929925, -1.6106710617710007},
			{103.62071435707355, -1.6106229269090022},
			{103.62061472834131, -1.6104420062116702},
			{103.62052506248301, -1.6105001000148462},
		},
	}

	// Call the function being tested
	result := Polygon(mconn, coordinates)

	// Add your assertions based on expected behavior
	expectedResult := ""
	if result != expectedResult {
		t.Errorf("Expected '%s', got '%s'", expectedResult, result)
	}
}

func GeoWithin(mongoconn *mongo.Database, coordinates [][][]float64) (namalokasi []string) {
	lokasicollection := mongoconn.Collection("petapediaaa")
	filter := bson.M{
		"geometry": bson.M{
			"$geoWithin": bson.M{
				"$geometry": bson.M{
					"type":        "Polygon",
					"coordinates": coordinates,
				},
			},
		},
	}

	cursor, err := lokasicollection.Find(context.TODO(), filter)
	if err != nil {
		log.Printf("GeoWithin: %v\n", err)
		return nil
	}
	defer cursor.Close(context.TODO())

	var lokasi Lokasi
	for cursor.Next(context.TODO()) {
		err := cursor.Decode(&lokasi)
		if err != nil {
			log.Printf("GeoWithin: %v\n", err)
			continue
		}
		namalokasi = append(namalokasi, lokasi.Properties.Name)
	}

	if err := cursor.Err(); err != nil {
		log.Printf("GeoWithin: %v\n", err)
	}

	return namalokasi
}

func saveFile(file multipart.File, filepath string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, file)
	return err
}
func Near(mongoconn *mongo.Database, long float64, lat float64, max float64, min float64) ([]string, error) {
	lokasicollection := mongoconn.Collection("near")
	filter := bson.M{
		"geometry": bson.M{
			"$near": bson.M{
				"$geometry": bson.M{
					"type":        "LineString",
					"coordinates": []float64{long, lat},
				},
				"$maxDistance": max,
				"$minDistance": min,
			},
		},
	}
	cur, err := lokasicollection.Find(context.TODO(), filter)
	if err != nil {
		log.Printf("Near: %v\n", err)
		return nil, err
	}
	defer cur.Close(context.TODO())

	var names []string
	for cur.Next(context.TODO()) {
		var lokasi Lokasi
		err := cur.Decode(&lokasi)
		if err != nil {
			log.Printf("Decode Err: %v\n", err)
			continue
		}
		names = append(names, lokasi.Properties.Name)
	}

	if err := cur.Err(); err != nil {
		log.Printf("Cursor Err: %v\n", err)
		return nil, err
	}

	return names, nil
}

// Modify the NearSpehere function
func NearSpehere(mongoconn *mongo.Database, long float64, lat float64) ([]string, error) {
	lokasicollection := mongoconn.Collection("near")
	filter := bson.M{
		"geometry": bson.M{
			"$nearSphere": bson.M{
				"$geometry": bson.M{
					"type":        "LineString",
					"coordinates": []float64{long, lat},
				},
				"$maxDistance": 1000,
			},
		},
	}
	var lokasis []Lokasi
	cur, err := lokasicollection.Find(context.TODO(), filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(context.TODO())

	for cur.Next(context.TODO()) {
		var lokasi Lokasi
		err := cur.Decode(&lokasi)
		if err != nil {
			fmt.Printf("Decode Err: %v\n", err)
			continue
		}
		lokasis = append(lokasis, lokasi)
	}

	if err := cur.Err(); err != nil {
		return nil, err
	}

	// Extract names from lokasis
	var names []string
	for _, doc := range lokasis {
		names = append(names, doc.Properties.Name)
	}

	return names, nil
}

func Polygonn(mongoconn *mongo.Database, coordinates [][][]float64) (namalokasi string) {
	lokasicollection := mongoconn.Collection("polygon")

	// Log coordinates for debugging
	fmt.Println("Coordinates:", coordinates)

	filter := bson.M{
		"geometry": bson.M{
			"$geoWithin": bson.M{
				"$geometry": bson.M{
					"type":        "Polygon",
					"coordinates": coordinates,
				},
			},
		},
	}

	fmt.Println("Filter:", filter)

	var lokasi Lokasi
	err := lokasicollection.FindOne(context.TODO(), filter).Decode(&lokasi)
	if err != nil {
		log.Printf("Polygon: %v\n", err)
		return ""
	}

	return lokasi.Properties.Name
}

func GetBoxDoccc(mongoconn *mongo.Database, coordinates Polyline) (result string, err error) {
	lokasicollection := mongoconn.Collection("boxfix")
	filter := bson.M{
		"geometry": bson.M{
			"$geoWithin": bson.M{
				"$box": coordinates.Coordinates,
			},
		},
	}

	cursor, err := lokasicollection.Find(context.TODO(), filter)
	if err != nil {
		fmt.Printf("Box: %v\n", err)
		return "", err
	}
	defer cursor.Close(context.TODO())

	var results []string
	for cursor.Next(context.TODO()) {
		var doc FullGeoJson
		err := cursor.Decode(&doc)
		if err != nil {
			fmt.Printf("Decode Err: %v\n", err)
			continue
		}
		results = append(results, doc.Properties.Name)
	}

	if err := cursor.Err(); err != nil {
		fmt.Printf("Cursor Err: %v\n", err)
		return "", err
	}

	// If no results found
	if len(results) == 0 {
		return "No matching documents found", nil
	}

	// Concatenate the results into a string
	result = "Box anda berada pada " + strings.Join(results, ", ")

	return result, nil
}

func Center(mongoconn *mongo.Database, longitude, latitude, radius float64) (namalokasi string) {
	lokasicollection := mongoconn.Collection("center")
	filter := bson.M{
		"geometry": bson.M{
			"$geoWithin": bson.M{
				"$centerSphere": []interface{}{[]float64{longitude, latitude}, float64(radius) / 6371000},
			},
		},
	}
	var lokasi Lokasi
	err := lokasicollection.FindOne(context.TODO(), filter).Decode(&lokasi)
	if err != nil {
		fmt.Printf("Center: %v\n", err)
	}
	return lokasi.Properties.Name
}

func MaxDistancee(mongoconn *mongo.Database, point []float64, maxdistance float64) (namalokasi string) {
	lokasicollection := mongoconn.Collection("max")
	filter := bson.M{
		"geometry": bson.M{
			"$near": bson.M{
				"$geometry":    bson.M{"type": "Point", "coordinates": point},
				"$maxDistance": maxdistance,
			},
		},
	}
	var lokasi Lokasi
	err := lokasicollection.FindOne(context.TODO(), filter).Decode(&lokasi)
	if err != nil {
		fmt.Printf("MaxDistancee: %v\n", err)
	}
	return lokasi.Properties.Name
}

func MinDistancee(mongoconn *mongo.Database, point []float64, minDistance float64) (namalokasi string) {
	lokasicollection := mongoconn.Collection("max")
	filter := bson.M{
		"geometry": bson.M{
			"$near": bson.M{
				"$geometry":    bson.M{"type": "Point", "coordinates": point},
				"$maxDistance": minDistance,
			},
		},
	}
	var lokasi Lokasi
	err := lokasicollection.FindOne(context.TODO(), filter).Decode(&lokasi)
	if err != nil {
		fmt.Printf("MaxDistancee: %v\n", err)
	}
	return lokasi.Properties.Name
}

func Geometryyy(mongoconn *mongo.Database, coordinates [][][]float64) (namalokasi string) {
	lokasicollection := mongoconn.Collection("geometry")
	filter := bson.M{
		"geometry": bson.M{
			"$geoWithin": bson.M{
				"$geometry": bson.M{
					"type":        "Polygon",
					"coordinates": coordinates,
				},
			},
		},
	}
	var lokasi Lokasi
	err := lokasicollection.FindOne(context.TODO(), filter).Decode(&lokasi)
	if err != nil {
		log.Printf("GeoWithin: %v\n", err)
	}
	return lokasi.Properties.Name
}
