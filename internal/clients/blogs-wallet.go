package clients

import (
	"encoding/json"
	"fmt"
	"github.com/Khvan-Group/auth-service/internal/common/models"
	"github.com/Khvan-Group/common-library/constants"
	"github.com/Khvan-Group/common-library/errors"
	"github.com/Khvan-Group/common-library/utils"
	"github.com/go-resty/resty/v2"
	"net/http"
)

var (
	BLOG_SERVICE_URL   string
	WALLET_SERVICE_URL string
)

func GetWalletByUser(username string, client *resty.Client) (*models.Wallet, *errors.CustomError) {
	var result models.Wallet
	WALLET_SERVICE_URL = utils.GetEnv("WALLET_SERVICE_URL")
	request := client.R()
	request.Header.Set(constants.X_IS_INTERNAL_SERVICE, "true")

	response, err := request.Get(WALLET_SERVICE_URL + "/wallets/" + username)
	if err != nil {
		return nil, errors.NewInternal("Внутренняя ошибка: Возможно сервис кошельков не доступен.")
	}

	if response.StatusCode() != http.StatusOK {
		return nil, errors.NewBadRequest("Ошибка получения кошелька пользователя.")
	}

	if err = json.Unmarshal(response.Body(), &result); err != nil {
		return nil, errors.NewInternal("Failed unmarshalling wallet response body")
	}

	return &result, nil
}

func DeleteUserDependencies(username string, client *resty.Client) *errors.CustomError {
	BLOG_SERVICE_URL = utils.GetEnv("BLOG_SERVICE_URL")
	WALLET_SERVICE_URL = utils.GetEnv("WALLET_SERVICE_URL")
	request := client.R()
	request.Header.Set(constants.X_IS_INTERNAL_SERVICE, "true")

	if err := deleteBlogsByUser(request, username); err != nil {
		return err
	}

	if err := deleteWalletByUser(request, username); err != nil {
		return err
	}

	return nil
}

func deleteBlogsByUser(request *resty.Request, username string) *errors.CustomError {
	response, err := request.Delete(fmt.Sprintf(BLOG_SERVICE_URL+"/blogs/%s/delete/", username))
	if err != nil {
		return errors.NewInternal("Внутренняя ошибка: Возможно сервис блогов недоступен.")
	}

	if response.StatusCode() != http.StatusOK {
		return errors.NewInternal("Ошибка удаления блогов при удалении пользователя.")
	}

	return nil
}

func deleteWalletByUser(request *resty.Request, username string) *errors.CustomError {
	response, err := request.Delete(WALLET_SERVICE_URL + "/wallets/" + username)
	if err != nil {
		return errors.NewInternal("Внутренняя ошибка: Возможно сервис кошельков недоступен.")
	}

	if response.StatusCode() != http.StatusOK {
		return errors.NewInternal("Ошибка удаления кошелька при удалении пользователя.")
	}

	return nil
}
