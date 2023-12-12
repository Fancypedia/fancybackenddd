package main

import (
	"fmt"
	"log"
	"net/http"

	peda "github.com/Fancypedia/fancybackenddd"
)

func HelloHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.GCFUpdateFE("0d6171e848ee9efe0eca37a10813d12ecc9930d6f9b11d7ea594cac48648f022", "MONGOULBI", "proyek3", "dosen", "frontend", r))
}

func handlerRequests() {
	http.HandleFunc("/", HelloHTTP)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	handlerRequests()
}
