package preflight

import (
	"goipsec/pkg/glog"
	"os"
)

func Checklist() {
	glog.Logger.Print("INFO: starting preflight checklist")

	if len(os.Getenv("GOIPSEC_KEY")) != 32 {
		glog.Logger.Println(os.Getenv("GOIPSEC_KEY"))
		glog.Logger.Fatal("ERROR: env variable GOIPSEC_KEY not found")
	} else {
		glog.Logger.Print("INFO: env variable GOIPSEC_KEY OK")
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		glog.Logger.Fatalf("ERROR: config directory not found: %s\n", err)
	}

	if _, err := os.Open(configDir + "/goipsec.json"); err != nil {
		glog.Logger.Fatalf("ERROR: config file not found: %s\n", err)
	}

	glog.Logger.Print("INFO: preflight checklist OK")
}
