package glog

import (
	"log"
	"os"
)

var Logger *log.Logger = log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)
