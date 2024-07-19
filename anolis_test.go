package anolis

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	config := NewConfig()
	assert.NotNil(t, config.AppFs, "AppFs should be initialized")
	assert.Equal(t, ovalURL, config.URL, "URL should be equal to ovalURL constant")
	assert.Equal(t, retry, config.Retry, "Retry should be equal to retry constant")
}

func TestUpdateValidOval(t *testing.T) {
	// 启动一个模拟的 HTTP 服务器来提供文件内容
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadFile(filepath.Join("testdata", "valid_anolis_oval.xml"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}))
	defer server.Close()

	config := NewConfig()
	config.URL = server.URL
	config.AppFs = afero.NewOsFs()

	err := config.Update()
	assert.Nil(t, err, "Update() should not return an error for valid OVAL data")
}

func TestUpdateInvalidOval(t *testing.T) {
	// 启动一个模拟的 HTTP 服务器来提供文件内容
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadFile(filepath.Join("testdata", "invalid_anolis_oval.xml"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}))
	defer server.Close()

	config := NewConfig()
	config.URL = server.URL
	config.AppFs = afero.NewOsFs()

	err := config.Update()
	assert.NotNil(t, err, "Update() should return an error for invalid OVAL data")
}
