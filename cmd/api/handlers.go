package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/tsawler/toolbox"
)

func (app *Config) Authenticate(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	tools := toolbox.Tools{}

	err := tools.ReadJSON(w, r, &requestPayload)
	if err != nil {
		tools.ErrorJSON(w, err, http.StatusBadRequest)
	}

	// validate user against the database
	user, err := app.Models.User.GetByEmail(requestPayload.Email)
	if err != nil {
		tools.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	valid, err := user.PasswordMatches(requestPayload.Password)
	if err != nil || !valid {
		tools.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	err = app.logRequest("authentication", fmt.Sprintf("%s logged in", user.Email))
	if err != nil {
		tools.ErrorJSON(w, err)
		return
	}

	payload := toolbox.JSONResponse{
		Error:   false,
		Message: fmt.Sprintf("Logged in user %s", user.Email),
		Data:    user,
	}

	tools.WriteJSON(w, http.StatusAccepted, payload)
}

func (app *Config) logRequest(name, data string) error {
	var entry struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}

	entry.Name = name
	entry.Data = data

	jsonData, _ := json.MarshalIndent(entry, "", "\t")
	logServiceURL := "http://logger-service/log"

	request, err := http.NewRequest("POST", logServiceURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	client := &http.Client{}
	_, err = client.Do(request)
	if err != nil {
		return err
	}

	return nil

}
