package rabbitmq

import (
	"encoding/json"
	"github.com/Khvan-Group/auth-service/internal/api"
	wallet "github.com/Khvan-Group/auth-service/internal/common/models"
	"github.com/Khvan-Group/common-library/constants"
	"github.com/Khvan-Group/common-library/errors"
	"github.com/Khvan-Group/common-library/logger"
	"github.com/Khvan-Group/common-library/utils"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func SendToWallet(msg wallet.Wallet) *errors.CustomError {
	data, err := json.Marshal(msg)
	if err != nil {
		return errors.NewInternal("Failed json marshaling wallet")
	}

	err = RabbitMQChannel.Publish("", utils.GetEnv(constants.RABBIT_CREATE_WALLET_QUEUE), false, false, amqp.Publishing{
		ContentType: api.APPLICATION_JSON,
		Body:        data,
	})

	if err != nil {
		logger.Logger.Fatal("Failed to publish a message to RabbitMQ wallet queue: %v", zap.String("username", msg.User), zap.Int("total", msg.Total))
		return errors.NewInternal("Failed to publish a message to RabbitMQ wallet queue")
	}

	return nil
}
