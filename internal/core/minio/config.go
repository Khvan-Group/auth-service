package minio

import (
	"github.com/Khvan-Group/common-library/constants"
	"github.com/Khvan-Group/common-library/utils"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"log"
)

var MinioClient *minio.Client

func InitMinio() {
	url := utils.GetEnv(constants.MINIO_URL)
	username := utils.GetEnv(constants.MINIO_USER)
	password := utils.GetEnv(constants.MINIO_PASSWORD)
	useSSL := false

	minioClient, err := minio.New(url, &minio.Options{
		Creds:  credentials.NewStaticV4(username, password, ""),
		Secure: useSSL,
	})
	if err != nil {
		log.Fatal(err)
	}

	MinioClient = minioClient
}
