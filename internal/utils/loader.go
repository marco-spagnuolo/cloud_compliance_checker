package utils

import (
	"encoding/json"
	"io/ioutil"
)

type Control struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Criteria    []Criteria `json:"criteria"`
}

type Criteria struct {
	Description   string `json:"description"`
	CheckFunction string `json:"check_function"`
	Value         int    `json:"value"`
}

type NISTControls struct {
	Controls  []Control      `json:"controls"`
	Responses map[string]int `json:"responses"`
}

func LoadControls(filename string) (NISTControls, error) {
	var controls NISTControls
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return controls, err
	}
	err = json.Unmarshal(data, &controls)
	return controls, err
}
