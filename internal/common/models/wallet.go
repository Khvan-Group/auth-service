package models

type Wallet struct {
	User  string `json:"username" database:"username"`
	Total int    `json:"total" database:"total"`
}
