package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

var ErrNotSupportedAuthorizationState = errors.New("not supported state")

const AuthCheckTimeout = 1 * time.Millisecond

// Contains parameters for TDLib initialization
type TdlibParameters struct {
	// Pass true to use Telegram test environment instead of the production environment
	UseTestDc bool `json:"use_test_dc"`
	// The path to the directory for the persistent database; if empty, the current working directory will be used
	DatabaseDirectory string `json:"database_directory"`
	// The path to the directory for storing files; if empty, database_directory will be used
	FilesDirectory string `json:"files_directory"`
	// Encryption key for the database. If the encryption key is invalid, then an error with code 401 will be returned
	DatabaseEncryptionKey []byte `json:"database_encryption_key"`
	// Pass true to keep information about downloaded and uploaded files between application restarts
	UseFileDatabase bool `json:"use_file_database"`
	// Pass true to keep cache of users, basic groups, supergroups, channels and secret chats between restarts. Implies use_file_database
	UseChatInfoDatabase bool `json:"use_chat_info_database"`
	// Pass true to keep cache of chats and messages between restarts. Implies use_chat_info_database
	UseMessageDatabase bool `json:"use_message_database"`
	// Pass true to enable support for secret chats
	UseSecretChats bool `json:"use_secret_chats"`
	// Application identifier for Telegram API access, which can be obtained at https://my.telegram.org
	ApiId int32 `json:"api_id"`
	// Application identifier hash for Telegram API access, which can be obtained at https://my.telegram.org
	ApiHash string `json:"api_hash"`
	// IETF language tag of the user's operating system language; must be non-empty
	SystemLanguageCode string `json:"system_language_code"`
	// Model of the device the application is being run on; must be non-empty
	DeviceModel string `json:"device_model"`
	// Version of the operating system the application is being run on. If empty, the version is automatically detected by TDLib
	SystemVersion string `json:"system_version"`
	// Application version; must be non-empty
	ApplicationVersion string `json:"application_version"`
	// Pass true to automatically delete old files in background
	EnableStorageOptimizer bool `json:"enable_storage_optimizer"`
	// Pass true to ignore original file names for downloaded files. Otherwise, downloaded files are saved under names as close as possible to the original name
	IgnoreFileNames bool `json:"ignore_file_names"`
}

type AuthorizationStateHandler interface {
	Context() context.Context
	Handle(client *Client, state AuthorizationState) error
	Error(err error)
	Close()
}

func Authorize(client *Client, authorizationStateHandler AuthorizationStateHandler) error {
	defer authorizationStateHandler.Close()

	var authorizationError error

	for {
		select {
		case <-time.After(AuthCheckTimeout):
			state, err := client.GetAuthorizationState()
			if err != nil {
				return err
			}

			err = authorizationStateHandler.Handle(client, state)
			if err != nil {
				authorizationError = err
				client.Close()
			}

			if state.AuthorizationStateType() == TypeAuthorizationStateClosed {
				return authorizationError
			}

			if state.AuthorizationStateType() == TypeAuthorizationStateReady {
				// dirty hack for db flush after authorization
				time.Sleep(1 * time.Second)
				return nil
			}

		case <-authorizationStateHandler.Context().Done():
			return nil
		}
	}
}

type clientAuthorizer struct {
	TdlibParameters chan *TdlibParameters
	PhoneNumber     chan string
	Code            chan string
	State           chan AuthorizationState
	Password        chan string
}

func ClientAuthorizer() *clientAuthorizer {
	return &clientAuthorizer{
		TdlibParameters: make(chan *TdlibParameters, 1),
		PhoneNumber:     make(chan string, 1),
		Code:            make(chan string, 1),
		State:           make(chan AuthorizationState, 10),
		Password:        make(chan string, 1),
	}
}

func (stateHandler *clientAuthorizer) Error(err error) {
	log.Fatalf("Authorization error: %s", err)
}

func (stateHandler *clientAuthorizer) Context() context.Context {
	return context.Background()
}

func (stateHandler *clientAuthorizer) Handle(client *Client, state AuthorizationState) error {
	stateHandler.State <- state

	switch state.AuthorizationStateType() {
	case TypeAuthorizationStateWaitTdlibParameters:
		p := <-stateHandler.TdlibParameters
		_, err := client.SetTdlibParameters(&SetTdlibParametersRequest{
			UseTestDc:              p.UseTestDc,
			DatabaseDirectory:      p.DatabaseDirectory,
			FilesDirectory:         p.FilesDirectory,
			DatabaseEncryptionKey:  p.DatabaseEncryptionKey,
			UseFileDatabase:        p.UseFileDatabase,
			UseChatInfoDatabase:    p.UseChatInfoDatabase,
			UseMessageDatabase:     p.UseMessageDatabase,
			UseSecretChats:         p.UseSecretChats,
			ApiId:                  p.ApiId,
			ApiHash:                p.ApiHash,
			SystemLanguageCode:     p.SystemLanguageCode,
			DeviceModel:            p.DeviceModel,
			SystemVersion:          p.SystemVersion,
			ApplicationVersion:     p.ApplicationVersion,
			EnableStorageOptimizer: p.EnableStorageOptimizer,
			IgnoreFileNames:        p.IgnoreFileNames,
		})
		return err

	case TypeAuthorizationStateWaitPhoneNumber:
		_, err := client.SetAuthenticationPhoneNumber(&SetAuthenticationPhoneNumberRequest{
			PhoneNumber: <-stateHandler.PhoneNumber,
			Settings: &PhoneNumberAuthenticationSettings{
				AllowFlashCall:       false,
				IsCurrentPhoneNumber: false,
				AllowSmsRetrieverApi: false,
			},
		})
		return err

	case TypeAuthorizationStateWaitEmailAddress:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateWaitEmailCode:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateWaitCode:
		_, err := client.CheckAuthenticationCode(&CheckAuthenticationCodeRequest{
			Code: <-stateHandler.Code,
		})
		return err

	case TypeAuthorizationStateWaitOtherDeviceConfirmation:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateWaitRegistration:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateWaitPassword:
		_, err := client.CheckAuthenticationPassword(&CheckAuthenticationPasswordRequest{
			Password: <-stateHandler.Password,
		})
		return err

	case TypeAuthorizationStateReady:
		return nil

	case TypeAuthorizationStateLoggingOut:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateClosing:
		return nil

	case TypeAuthorizationStateClosed:
		return nil
	}

	return ErrNotSupportedAuthorizationState
}

func (stateHandler *clientAuthorizer) Close() {
	close(stateHandler.TdlibParameters)
	close(stateHandler.PhoneNumber)
	close(stateHandler.Code)
	close(stateHandler.State)
	close(stateHandler.Password)
}

func CliInteractor(clientAuthorizer *clientAuthorizer) {
	for {
		select {
		case state, ok := <-clientAuthorizer.State:
			if !ok {
				return
			}

			switch state.AuthorizationStateType() {
			case TypeAuthorizationStateWaitPhoneNumber:
				fmt.Println("Enter phone number: ")
				var phoneNumber string
				fmt.Scanln(&phoneNumber)

				clientAuthorizer.PhoneNumber <- phoneNumber

			case TypeAuthorizationStateWaitEmailAddress:
				return

			case TypeAuthorizationStateWaitEmailCode:
				return

			case TypeAuthorizationStateWaitCode:
				var code string

				fmt.Println("Enter code: ")
				fmt.Scanln(&code)

				clientAuthorizer.Code <- code

			case TypeAuthorizationStateWaitOtherDeviceConfirmation:
				return

			case TypeAuthorizationStateWaitRegistration:
				return

			case TypeAuthorizationStateWaitPassword:
				fmt.Println("Enter password: ")
				var password string
				fmt.Scanln(&password)

				clientAuthorizer.Password <- password

			case TypeAuthorizationStateReady:
				return
			}
		}
	}
}

type botAuthorizer struct {
	TdlibParameters chan *TdlibParameters
	Token           chan string
	State           chan AuthorizationState
}

func BotAuthorizer(token string) *botAuthorizer {
	botAuthorizer := &botAuthorizer{
		TdlibParameters: make(chan *TdlibParameters, 1),
		Token:           make(chan string, 1),
		State:           make(chan AuthorizationState, 10),
	}

	botAuthorizer.Token <- token

	return botAuthorizer
}

func (stateHandler *botAuthorizer) Error(err error) {
	log.Fatalf("Authorization error: %s", err)
}

func (stateHandler *botAuthorizer) Context() context.Context {
	return context.Background()
}

func (stateHandler *botAuthorizer) Handle(client *Client, state AuthorizationState) error {
	stateHandler.State <- state

	switch state.AuthorizationStateType() {
	case TypeAuthorizationStateWaitTdlibParameters:
		p := <-stateHandler.TdlibParameters
		_, err := client.SetTdlibParameters(&SetTdlibParametersRequest{
			UseTestDc:              p.UseTestDc,
			DatabaseDirectory:      p.DatabaseDirectory,
			FilesDirectory:         p.FilesDirectory,
			DatabaseEncryptionKey:  p.DatabaseEncryptionKey,
			UseFileDatabase:        p.UseFileDatabase,
			UseChatInfoDatabase:    p.UseChatInfoDatabase,
			UseMessageDatabase:     p.UseMessageDatabase,
			UseSecretChats:         p.UseSecretChats,
			ApiId:                  p.ApiId,
			ApiHash:                p.ApiHash,
			SystemLanguageCode:     p.SystemLanguageCode,
			DeviceModel:            p.DeviceModel,
			SystemVersion:          p.SystemVersion,
			ApplicationVersion:     p.ApplicationVersion,
			EnableStorageOptimizer: p.EnableStorageOptimizer,
			IgnoreFileNames:        p.IgnoreFileNames,
		})
		return err

	case TypeAuthorizationStateWaitPhoneNumber:
		_, err := client.CheckAuthenticationBotToken(&CheckAuthenticationBotTokenRequest{
			Token: <-stateHandler.Token,
		})
		return err

	case TypeAuthorizationStateWaitCode:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateWaitPassword:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateReady:
		return nil

	case TypeAuthorizationStateLoggingOut:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateClosing:
		return ErrNotSupportedAuthorizationState

	case TypeAuthorizationStateClosed:
		return ErrNotSupportedAuthorizationState
	}

	return ErrNotSupportedAuthorizationState
}

func (stateHandler *botAuthorizer) Close() {
	close(stateHandler.TdlibParameters)
	close(stateHandler.Token)
	close(stateHandler.State)
}
