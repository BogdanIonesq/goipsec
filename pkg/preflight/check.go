package preflight

import (
	"goipsec/pkg/glog"
	"os"
)

func Checklist() {
	glog.Logger.Print("INFO: starting checklist")

	if len(os.Getenv("GOIPSEC_PASSWORD")) != 32 {
		glog.Logger.Fatal("ERROR: env variable GOIPSEC_PASSWORD not found")
	} else {
		glog.Logger.Print("INFO: env variable GOIPSEC_PASSWORD found")
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		glog.Logger.Fatalf("ERROR: config directory not found: %s\n", err)
	}

	if _, err := os.Open(configDir + "/goipsec.conf"); err != nil {
		glog.Logger.Fatalf("ERROR: config file not found: %s\n", err)
	}
}
