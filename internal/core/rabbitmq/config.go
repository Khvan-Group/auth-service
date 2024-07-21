package rabbitmq

import (
	"fmt"
	"github.com/Khvan-Group/common-library/constants"
	"github.com/Khvan-Group/common-library/logger"
	"github.com/Khvan-Group/common-library/utils"
	amqp "github.com/rabbitmq/amqp091-go"
)

var RabbitMQChannel *amqp.Channel

func InitRabbitMQ() {
	amqpUrl := utils.GetEnv("RABBIT_URL")
	amqpPort := utils.GetEnv("RABBIT_PORT")
	amqpUser := utils.GetEnv("RABBIT_USER")
	amqpPass := utils.GetEnv("RABBIT_PASS")
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s", amqpUser, amqpPass, amqpUrl, amqpPort))
	if err != nil {
		logger.Logger.Fatal("Failed to connect to RabbitMQ")
		return
	}

	RabbitMQChannel, err = conn.Channel()
	if err != nil {
		logger.Logger.Fatal("Failed to get RabbitMQ channel")
		return
	}

	_, err = RabbitMQChannel.QueueDeclare(
		utils.GetEnv(constants.RABBIT_CREATE_WALLET_QUEUE),
		false,
		false,
		false,
		false,
		nil,
	)

	if err != nil {
		logger.Logger.Fatal("Failed to declare RabbitMQ queue")
		return
	}
}
